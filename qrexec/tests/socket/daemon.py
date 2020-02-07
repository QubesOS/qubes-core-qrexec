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
from typing import Tuple

import psutil

from . import qrexec
from . import util

ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                         '..', '..', '..'))


@unittest.skipIf(os.environ.get('SKIP_SOCKET_TESTS'),
                 'socket tests not set up')
class TestDaemon(unittest.TestCase):
    daemon = None
    domain = 42
    domain_name = 'domain_name'

    # Stub qrexec-policy-exec program.
    # Strictly speaking, the program should also run qrexec-client in case the
    # call is allowed, but we will simulate that elsewhere.
    POLICY_PROGRAM = '''\
#!/bin/sh

echo "$@" > {tempdir}/qrexec-policy-params
exit 1
'''

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempdir)

    def start_daemon(self):
        policy_program_path = os.path.join(self.tempdir, 'qrexec-policy-exec')
        with open(policy_program_path, 'w') as f:
            f.write(self.POLICY_PROGRAM.format(tempdir=self.tempdir))
        os.chmod(policy_program_path, 0o700)

        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = os.path.join(ROOT_PATH, 'libqrexec')
        env['VCHAN_DOMAIN'] = '0'
        env['VCHAN_SOCKET_DIR'] = self.tempdir
        cmd = [
            os.path.join(ROOT_PATH, 'daemon', 'qrexec-daemon'),
            '--socket-dir=' + self.tempdir,
            '--policy-program=' + policy_program_path,
            '--direct',
            str(self.domain),
            self.domain_name,
        ]
        if os.environ.get('USE_STRACE'):
            cmd = ['strace', '-f'] + cmd
        self.daemon = subprocess.Popen(
            cmd,
            env=env,
        )
        self.addCleanup(self.stop_daemon)

    def stop_daemon(self):
        if self.daemon:
            self.wait_for_daemon_children()
            self.daemon.terminate()
            self.daemon.wait()
            self.daemon = None

    def wait_for_daemon_children(self):
        proc = psutil.Process(self.daemon.pid)
        children = proc.children(recursive=True)
        psutil.wait_procs(children)

    def get_policy_program_params(self):
        with open(os.path.join(self.tempdir, 'qrexec-policy-params')) as f:
            return f.read().split()

    def start_daemon_with_agent(self):
        agent = self.connect_agent()
        self.start_daemon()
        agent.accept()
        return agent

    def connect_agent(self):
        agent = qrexec.vchan_server(
            self.tempdir, self.domain, 0, 512)
        self.addCleanup(agent.close)
        return agent

    def connect_client(self):
        client = qrexec.socket_client(
            os.path.join(self.tempdir, 'qrexec.{}'.format(self.domain)))
        self.addCleanup(client.close)
        return client

    def test_handshake(self):
        agent = self.start_daemon_with_agent()
        agent.handshake()

    def test_trigger_service_refused(self):
        agent = self.start_daemon_with_agent()
        agent.handshake()

        target_domain_name = 'target_domain'
        ident = 'SOCKET42'

        message_type, data = self.trigger_service(
            agent, target_domain_name, 'qubes.ForbiddenServiceName', ident)
        self.assertEqual(message_type, qrexec.MSG_SERVICE_REFUSED)
        self.assertEqual(data, struct.pack('<32s', ident.encode()))

    def trigger_service(self,
                        agent,
                        target_domain_name: str,
                        service_name: str,
                        ident: str) -> Tuple[int, bytes]:
        agent.send_message(
            qrexec.MSG_TRIGGER_SERVICE3,
            struct.pack('<64s32s',
                        target_domain_name.encode(), ident.encode()) +
            service_name.encode() + b'\0'
        )
        message_type, data = agent.recv_message()
        self.assertListEqual(self.get_policy_program_params(), [
            '--',
            str(self.domain),
            self.domain_name,
            target_domain_name,
            service_name,
            ident
        ])

        return message_type, data

    def test_client_handshake(self):
        agent = self.start_daemon_with_agent()
        agent.handshake()

        client = self.connect_client()
        client.handshake()

    def test_restart_agent(self):
        agent = self.start_daemon_with_agent()
        agent.handshake()

        agent.close()

        util.wait_until(
            lambda: not os.path.exists(
                os.path.join(self.tempdir, 'qrexec.{}'.format(self.domain))),
            'socket deleted')

        agent = self.connect_agent()
        agent.accept()
        agent.handshake()

        # Now, new client should be able to connect
        client = self.connect_client()
        client.handshake()

    def test_client_exec(self):
        agent = self.start_daemon_with_agent()
        agent.handshake()

        cmd = 'user:echo Hello world'
        port = self.client_exec(0, cmd, qrexec.MSG_JUST_EXEC)

        message_type, data = agent.recv_message()
        self.assertEqual(message_type, qrexec.MSG_JUST_EXEC)
        self.assertEqual(data,
                         struct.pack('<LL', 0, port) +
                         cmd.encode() + b'\0')

    def client_exec(self,
                    domain: int,
                    cmd: str = 'user:echo Hello world',
                    message_type: int = qrexec.MSG_JUST_EXEC):
        client = self.connect_client()
        client.handshake()

        client.send_message(
            message_type,
            struct.pack('<LL', domain, 0) +
            cmd.encode() + b'\0')

        message_type, data = client.recv_message()
        self.assertEqual(message_type, qrexec.MSG_JUST_EXEC)
        domain, port = struct.unpack('<LL', data)
        self.assertEqual(domain, self.domain)

        return port

    def test_client_exec_allocates_next_port(self):
        agent = self.start_daemon_with_agent()
        agent.handshake()

        domain1 = self.domain + 1
        domain2 = self.domain + 2
        port = self.client_exec(domain1)
        self.assertEqual(port, 513)
        port = self.client_exec(domain2)
        self.assertEqual(port, 514)

    def test_client_exec_connection_terminated(self):
        agent = self.start_daemon_with_agent()
        agent.handshake()

        domain1 = self.domain + 1
        domain2 = self.domain + 2
        port = self.client_exec(domain1)
        self.assertEqual(port, 513)
        agent.send_message(qrexec.MSG_CONNECTION_TERMINATED,
                           struct.pack('<LL', domain1, port))
        port = self.client_exec(domain2)
        self.assertEqual(port, 513)

    def test_client_service_connect(self):
        agent = self.start_daemon_with_agent()
        agent.handshake()

        client = self.connect_client()
        client.handshake()

        target_domain = self.domain + 1
        target_port = 513
        ident = 'SOCKET11'

        data = (struct.pack('<LL', target_domain, target_port) +
                ident.encode() + b'\0')

        client.send_message(qrexec.MSG_SERVICE_CONNECT, data)
        self.assertEqual(agent.recv_message(),
                         (qrexec.MSG_SERVICE_CONNECT, data))


@unittest.skipIf(os.environ.get('SKIP_SOCKET_TESTS'),
                 'socket tests not set up')
class TestClient(unittest.TestCase):
    client = None

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempdir)

    def start_client(self, args):
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = os.path.join(ROOT_PATH, 'libqrexec')
        env['VCHAN_DOMAIN'] = '0'
        env['VCHAN_SOCKET_DIR'] = self.tempdir
        cmd = [
            os.path.join(ROOT_PATH, 'daemon', 'qrexec-client'),
            '--socket-dir=' + self.tempdir,
        ] + args
        if os.environ.get('USE_STRACE'):
            cmd = ['strace', '-f'] + cmd
        self.client = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
        )
        self.addCleanup(self.stop_client)

    def stop_client(self):
        if self.client:
            self.client.terminate()
            self.client.communicate()
            self.client = None

    def connect_daemon(self, domain_name):
        daemon = qrexec.socket_server(
            os.path.join(self.tempdir, 'qrexec.{}'.format(domain_name)))
        self.addCleanup(daemon.close)
        return daemon

    def connect_target(self, domain, port):
        target = qrexec.vchan_client(self.tempdir, 0, domain, port)
        self.addCleanup(target.close)
        return target

    def connect_source(self, domain, port):
        source = qrexec.vchan_server(self.tempdir, domain, 0, port)
        self.addCleanup(source.close)
        return source

    def test_run_vm_command_from_dom0(self):
        cmd = 'user:command'
        target_domain_name = 'target_domain'
        target_domain = 42
        target_port = 513

        target_daemon = self.connect_daemon(target_domain_name)
        self.start_client(['-d', target_domain_name, cmd])
        target_daemon.accept()
        target_daemon.handshake()

        # negotiate_connection_params
        self.assertEqual(
            target_daemon.recv_message(),
            (qrexec.MSG_EXEC_CMDLINE,
             struct.pack('<LL', 0, 0) + cmd.encode() + b'\0'))
        target_daemon.send_message(
            qrexec.MSG_EXEC_CMDLINE,
            struct.pack('<LL', target_domain, target_port))

        target = self.connect_target(target_domain, target_port)
        target.handshake()

        # select_loop
        target.send_message(qrexec.MSG_DATA_STDOUT, b'stdout data\n')
        target.send_message(qrexec.MSG_DATA_STDOUT, b'')
        self.assertEqual(self.client.stdout.read(), b'stdout data\n')
        target.send_message(qrexec.MSG_DATA_EXIT_CODE,
                                   struct.pack('<L', 42))
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_run_vm_command_and_connect_vm(self):
        cmd = 'user:command'
        request_id = 'SOCKET11'
        src_domain_name = 'src_domain'
        src_domain = 43
        target_domain_name = 'target_domain'
        target_domain = 42
        target_port = 513

        target_daemon = self.connect_daemon(target_domain_name)
        src_daemon = self.connect_daemon(src_domain_name)

        self.start_client([
            '-d', target_domain_name,
            '-c', '{},{},{}'.format(
                request_id, src_domain_name, src_domain),
            cmd,
        ])

        target_daemon.accept()
        target_daemon.handshake()

        # negotiate_connection_params
        self.assertEqual(
            target_daemon.recv_message(),
            (qrexec.MSG_EXEC_CMDLINE,
             struct.pack('<LL', src_domain, 0) + cmd.encode() + b'\0'))
        target_daemon.send_message(
            qrexec.MSG_EXEC_CMDLINE,
            struct.pack('<LL', target_domain, target_port))

        # send_service_connect
        src_daemon.accept()
        src_daemon.handshake()
        self.assertEqual(
            src_daemon.recv_message(),
            (qrexec.MSG_SERVICE_CONNECT,
             struct.pack('<LL32s', target_domain, target_port,
                         request_id.encode())))
        self.client.wait()
        self.assertEqual(self.client.returncode, 0)

    def test_run_dom0_command_and_connect_vm(self):
        cmd = 'echo Hello world'
        request_id = 'SOCKET11'
        src_domain_name = 'src_domain'
        src_domain = 43
        src_port = 42

        src_daemon = self.connect_daemon(src_domain_name)
        source = self.connect_source(src_domain, src_port)

        self.start_client([
            '-d', 'dom0',
            '-c', '{},{},{}'.format(
                request_id, src_domain_name, src_domain),
            cmd,
        ])

        # negotiate_connection_params
        src_daemon.accept()
        src_daemon.handshake()
        self.assertEqual(
            src_daemon.recv_message(),
            (qrexec.MSG_SERVICE_CONNECT,
             struct.pack('<LL32s', 0, 0, request_id.encode())))
        src_daemon.send_message(
            qrexec.MSG_SERVICE_CONNECT,
            struct.pack('<LL', src_domain, src_port))

        source.accept()
        source.handshake()

        source.send_message(qrexec.MSG_DATA_STDIN, b'')
        self.assertEqual(source.recv_all_messages(), [
            (qrexec.MSG_DATA_STDOUT, b'Hello world\n'),
            (qrexec.MSG_DATA_STDOUT, b''),
            (qrexec.MSG_DATA_EXIT_CODE, b'\0\0\0\0'),
        ])
