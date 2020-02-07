# -*- encoding: utf-8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2020  Paweł Marczewski  <pawel@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.

import unittest
import subprocess
import os.path
import os
import tempfile
import shutil
import struct
import getpass
import psutil


from . import qrexec
from . import util


ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                         '..', '..', '..'))


@unittest.skipIf(os.environ.get('SKIP_SOCKET_TESTS'),
                 'socket tests not set up')
class TestAgentBase(unittest.TestCase):
    agent = None
    domain = 42
    target_domain = 43
    target_port = 1024

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempdir)

    def start_agent(self):
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = os.path.join(ROOT_PATH, 'libqrexec')
        env['VCHAN_DOMAIN'] = str(self.domain)
        env['VCHAN_SOCKET_DIR'] = self.tempdir
        cmd = [
            os.path.join(ROOT_PATH, 'agent', 'qrexec-agent'),
            '--no-fork-server',
            '--agent-socket=' + os.path.join(self.tempdir, 'agent.sock'),
        ]
        if os.environ.get('USE_STRACE'):
            cmd = ['strace', '-f'] + cmd
        self.agent = subprocess.Popen(
            cmd,
            env=env,
        )
        self.addCleanup(self.stop_agent)

    def stop_agent(self):
        if self.agent:
            self.wait_for_agent_children()
            self.agent.terminate()
            self.agent.wait()
            self.agent = None

    def wait_for_agent_children(self):
        proc = psutil.Process(self.agent.pid)
        children = proc.children(recursive=True)
        psutil.wait_procs(children)

    def connect_dom0(self):
        dom0 = qrexec.vchan_client(self.tempdir, self.domain, 0, 512)
        self.addCleanup(dom0.close)
        return dom0

    def connect_target(self):
        target = qrexec.vchan_server(
            self.tempdir, self.target_domain, self.domain, self.target_port)
        self.addCleanup(target.close)
        target.accept()
        return target

    def connect_client(self):
        client = qrexec.socket_client(os.path.join(self.tempdir, 'agent.sock'))
        self.addCleanup(client.close)
        return client


@unittest.skipIf(os.environ.get('SKIP_SOCKET_TESTS'),
                 'socket tests not set up')
class TestAgent(TestAgentBase):
    def test_handshake(self):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

    def test_just_exec(self):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

        user = getpass.getuser().encode('ascii')

        cmd = (('touch ' + os.path.join(self.tempdir, 'new_file'))
               .encode('ascii'))
        dom0.send_message(
            qrexec.MSG_JUST_EXEC,
            struct.pack('<LL', self.target_domain, self.target_port) +
            user + b':' + cmd + b'\0')

        target = self.connect_target()
        target.handshake()
        self.assertListEqual(target.recv_all_messages(), [
            (qrexec.MSG_DATA_EXIT_CODE, b'\0\0\0\0'),
        ])

        util.wait_until(
            lambda: os.path.exists(os.path.join(self.tempdir, 'new_file')),
            'file created')

        self.assertEqual(
            dom0.recv_message(),
            (qrexec.MSG_CONNECTION_TERMINATED,
             struct.pack('<LL', self.target_domain, self.target_port)))

    def test_exec_cmdline(self):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

        user = getpass.getuser().encode('ascii')

        dom0.send_message(
            qrexec.MSG_EXEC_CMDLINE,
            struct.pack('<LL', self.target_domain, self.target_port) +
            user + b':echo Hello world\0')

        target = self.connect_target()
        target.handshake()

        target.send_message(
            qrexec.MSG_DATA_STDIN,
            b'')

        messages = target.recv_all_messages()
        self.assertListEqual(util.sort_messages(messages), [
            (qrexec.MSG_DATA_STDOUT, b'Hello world\n'),
            (qrexec.MSG_DATA_STDOUT, b''),
            (qrexec.MSG_DATA_STDERR, b''),
            (qrexec.MSG_DATA_EXIT_CODE, b'\0\0\0\0'),
        ])

        self.assertEqual(
            dom0.recv_message(),
            (qrexec.MSG_CONNECTION_TERMINATED,
             struct.pack('<LL', self.target_domain, self.target_port)))

    def test_trigger_service(self):
        self.start_agent()

        target_domain_name = b'target_domain'

        dom0 = self.connect_dom0()
        dom0.handshake()

        client = self.connect_client()
        ident = self.trigger_service(
            dom0, client, target_domain_name, b'qubes.ServiceName')

        dom0.send_message(
            qrexec.MSG_SERVICE_CONNECT,
            struct.pack('<LL32s',
                        self.target_domain,
                        self.target_port,
                        ident))

        data = client.recvall(8)
        self.assertEqual(struct.unpack('<LL', data),
                         (self.target_domain, self.target_port))

        client.close()
        self.assertEqual(
            dom0.recv_message(),
            (qrexec.MSG_CONNECTION_TERMINATED,
             struct.pack('<LL', self.target_domain, self.target_port)))

    def test_trigger_service_refused(self):
        self.start_agent()

        target_domain_name = b'target_domain'

        dom0 = self.connect_dom0()
        dom0.handshake()

        client = self.connect_client()
        ident = self.trigger_service(
            dom0, client, target_domain_name, b'qubes.ServiceName')

        dom0.send_message(
            qrexec.MSG_SERVICE_REFUSED,
            struct.pack('<32s', ident))

        # agent should close connection to client
        data = client.recvall(8)
        self.assertEqual(data, b'')

    def trigger_service(self, dom0, client, target_domain_name, service_name):
        source_params = (
            struct.pack('<64s32s',
                        target_domain_name, b'SOCKET') +
            service_name + b'\0'
        )

        client.send_message(
            qrexec.MSG_TRIGGER_SERVICE3,
            source_params,
        )

        message_type, target_params = dom0.recv_message()
        self.assertEqual(message_type, qrexec.MSG_TRIGGER_SERVICE3)

        ident = target_params[64:96]
        ident = ident[:ident.find(b'\0')]
        self.assertTrue(ident.startswith(b'SOCKET'),
                        'wrong ident: {}'.format(ident))

        # The params should be the same except for ident.
        self.assertEqual(
            target_params,
            source_params[:64] + ident + source_params[64+len(ident):])

        return ident


@unittest.skipIf(os.environ.get('SKIP_SOCKET_TESTS'),
                 'socket tests not set up')
class TestAgentStreams(TestAgentBase):
    def execute(self, cmd: str):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

        user = getpass.getuser()
        cmdline = '{}:{}\0'.format(user, cmd).encode('ascii')

        dom0.send_message(
            qrexec.MSG_EXEC_CMDLINE,
            struct.pack('<LL', self.target_domain, self.target_port) +
            cmdline)

        target = self.connect_target()
        target.handshake()
        return target

    def test_stdin_stderr(self):
        target = self.execute('echo "stdout"; echo "stderr" >&2')
        target.send_message(qrexec.MSG_DATA_STDIN, b'')

        messages = target.recv_all_messages()
        self.assertListEqual(util.sort_messages(messages), [
            (qrexec.MSG_DATA_STDOUT, b'stdout\n'),
            (qrexec.MSG_DATA_STDOUT, b''),
            (qrexec.MSG_DATA_STDERR, b'stderr\n'),
            (qrexec.MSG_DATA_STDERR, b''),
            (qrexec.MSG_DATA_EXIT_CODE, b'\0\0\0\0')
        ])

    def test_pass_stdin(self):
        target = self.execute('cat')

        target.send_message(qrexec.MSG_DATA_STDIN, b'data 1')
        self.assertEqual(target.recv_message(),
                         (qrexec.MSG_DATA_STDOUT, b'data 1'))

        target.send_message(qrexec.MSG_DATA_STDIN, b'data 2')
        self.assertEqual(target.recv_message(),
                         (qrexec.MSG_DATA_STDOUT, b'data 2'))

        target.send_message(qrexec.MSG_DATA_STDIN, b'')
        messages = target.recv_all_messages()
        self.assertListEqual(util.sort_messages(messages), [
            (qrexec.MSG_DATA_STDOUT, b''),
            (qrexec.MSG_DATA_STDERR, b''),
            (qrexec.MSG_DATA_EXIT_CODE, b'\0\0\0\0')
        ])

    def test_close_stdin_early(self):
        target = self.execute('head -n1')

        target.send_message(qrexec.MSG_DATA_STDIN, b'data 1\n')
        target.send_message(qrexec.MSG_DATA_STDIN, b'data 2\n')
        target.send_message(qrexec.MSG_DATA_STDIN, b'')

        messages = target.recv_all_messages()
        self.assertListEqual(util.sort_messages(messages), [
            (qrexec.MSG_DATA_STDOUT, b'data 1\n'),
            (qrexec.MSG_DATA_STDOUT, b''),
            (qrexec.MSG_DATA_STDERR, b''),
            (qrexec.MSG_DATA_EXIT_CODE, b'\0\0\0\0')
        ])

    def test_close_stdout_stderr_early(self):
        target = self.execute('''\
read
echo closing stdout
exec >&-
read
echo closing stderr >&2
exec 2>&-
read code
exit $code
''')

        target.send_message(qrexec.MSG_DATA_STDIN, b'\n')

        self.assertEqual(target.recv_message(),
                         (qrexec.MSG_DATA_STDOUT, b'closing stdout\n'))
        self.assertEqual(target.recv_message(),
                         (qrexec.MSG_DATA_STDOUT, b''))

        target.send_message(qrexec.MSG_DATA_STDIN, b'\n')

        self.assertEqual(target.recv_message(),
                         (qrexec.MSG_DATA_STDERR, b'closing stderr\n'))
        self.assertEqual(target.recv_message(),
                         (qrexec.MSG_DATA_STDERR, b''))

        target.send_message(qrexec.MSG_DATA_STDIN, b'42\n')
        target.send_message(qrexec.MSG_DATA_STDIN, b'')
        self.assertEqual(target.recv_message(),
                         (qrexec.MSG_DATA_EXIT_CODE, struct.pack('<L', 42)))

    def test_stdio_socket(self):
        target = self.execute('''\
kill -USR1 $PPID
echo hello world >&0
read x
echo "received: $x" >&0
''')
        self.assertEqual(target.recv_message(),
                         (qrexec.MSG_DATA_STDOUT, b'hello world\n'))

        target.send_message(qrexec.MSG_DATA_STDIN, b'stdin\n')
        target.send_message(qrexec.MSG_DATA_STDIN, b'')

        messages = target.recv_all_messages()
        self.assertListEqual(util.sort_messages(messages), [
            (qrexec.MSG_DATA_STDOUT, b'received: stdin\n'),
            (qrexec.MSG_DATA_STDOUT, b''),
            (qrexec.MSG_DATA_STDERR, b''),
            (qrexec.MSG_DATA_EXIT_CODE, b'\0\0\0\0')
        ])


@unittest.skipIf(os.environ.get('SKIP_SOCKET_TESTS'),
                 'socket tests not set up')
class TestClientVm(unittest.TestCase):
    client = None
    domain = 42
    target_domain_name = 'target_domain'
    target_domain = 43
    target_port = 1024

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempdir)

    def start_client(self, args):
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = os.path.join(ROOT_PATH, 'libqrexec')
        env['VCHAN_DOMAIN'] = str(self.domain)
        env['VCHAN_SOCKET_DIR'] = self.tempdir
        env['QREXEC_NO_ROOT'] = '1'
        cmd = [
            os.path.join(ROOT_PATH, 'agent', 'qrexec-client-vm'),
            '--agent-socket=' + os.path.join(self.tempdir, 'agent.sock'),
        ] + args
        self.client = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop_client)

    def stop_client(self):
        if self.client:
            self.client.terminate()
            self.client.communicate()
            self.client = None

    def connect_server(self):
        server = qrexec.socket_server(os.path.join(self.tempdir, 'agent.sock'))
        self.addCleanup(server.close)
        return server

    def connect_target_client(self):
        target_client = qrexec.vchan_client(
            self.tempdir, self.domain, self.target_domain, self.target_port)
        self.addCleanup(target_client.close)
        return target_client

    def test_run_client(self):
        server = self.connect_server()
        self.start_client([self.target_domain_name, 'qubes.ServiceName'])
        server.accept()

        message_type, data = server.recv_message()
        self.assertEqual(message_type, qrexec.MSG_TRIGGER_SERVICE3)
        self.assertEqual(
            data,
            struct.pack('<64s32s',
                        self.target_domain_name.encode(), b'SOCKET') +
            b'qubes.ServiceName\0')

        server.sendall(struct.pack('<LL',
                                   self.target_domain, self.target_port))

        target_client = self.connect_target_client()
        target_client.handshake()
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b'stdout data\n')
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b'')
        self.assertEqual(self.client.stdout.read(), b'stdout data\n')
        target_client.send_message(qrexec.MSG_DATA_EXIT_CODE,
                                   struct.pack('<L', 42))
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_run_client_refused(self):
        server = self.connect_server()
        self.start_client([self.target_domain_name, 'qubes.ServiceName'])
        server.accept()

        message_type, __data = server.recv_message()
        self.assertEqual(message_type, qrexec.MSG_TRIGGER_SERVICE3)

        server.conn.close()
        self.client.wait()
        self.assertEqual(self.client.stdout.read(), b'')
        self.assertEqual(self.client.stderr.read(), b'Request refused\n')
        self.assertEqual(self.client.returncode, 126)
