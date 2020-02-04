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
import tempfile
import shutil
import time
import struct
import psutil
import getpass

from . import qrexec


ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))



class TestAgent(unittest.TestCase):
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
        env['QREXEC_NO_ROOT'] = '1'
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

    def wait_until(self, func, message, n_tries=10, delay=0.1):
        for _ in range(n_tries):
            if func():
                return
            time.sleep(delay)
        self.fail('Timed out waiting: ' + message)

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

        self.wait_until(
            lambda: os.path.exists(os.path.join(self.tempdir, 'new_file')),
            'file created')

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
        # Unfortunately, the order of two middle messages
        # (stdout/stderr end) is not deterministic.
        self.assertListEqual(sorted(messages), sorted([
            (qrexec.MSG_DATA_STDOUT, b'Hello world\n'),
            (qrexec.MSG_DATA_STDOUT, b''),
            (qrexec.MSG_DATA_STDERR, b''),
            (qrexec.MSG_DATA_EXIT_CODE, b'\0\0\0\0'),
        ]))

    def test_trigger_service(self):
        self.start_agent()

        target_domain_name = b'target_domain'

        dom0 = self.connect_dom0()
        dom0.handshake()

        client = self.connect_client()
        client.send_message(
            qrexec.MSG_TRIGGER_SERVICE3,
            struct.pack('<64s32s',
                        target_domain_name, b'SOCKET') +
            b'qubes.ServiceName\0'
        )

        message_type, data = dom0.recv_message()
        self.assertEqual(message_type, qrexec.MSG_TRIGGER_SERVICE3)

        target, ident = struct.unpack('<64s32s', data[:96])
        target = target[:target.find(b'\0')]
        ident = ident[:ident.find(b'\0')]
        self.assertEqual(target, target_domain_name)
        self.assertTrue(ident.startswith(b'SOCKET'),
                        'wrong ident: {}'.format(ident))

        service_name = data[96:]
        self.assertEqual(service_name, b'qubes.ServiceName\0')

        dom0.send_message(
            qrexec.MSG_SERVICE_CONNECT,
            struct.pack('<LL32s',
                        self.target_domain,
                        self.target_port,
                        ident))

        data = client.recvall(8)
        self.assertEqual(struct.unpack('<LL', data),
                         (self.target_domain, self.target_port))


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
            self.client.stdout.read()
            self.client.stdout.close()
            self.client.terminate()
            self.client.wait()
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
