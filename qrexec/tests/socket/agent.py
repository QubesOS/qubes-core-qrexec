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
import sys
import unittest
import subprocess
import os.path
import os
import tempfile
import shutil
import struct
import getpass
import itertools

import psutil
import pytest

from . import qrexec
from . import util


ROOT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)


@unittest.skipIf(os.environ.get("SKIP_SOCKET_TESTS"), "socket tests not set up")
class TestAgentBase(unittest.TestCase):
    agent = None
    domain = 42
    target_domain = 43
    target_port = 1024

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        os.mkdir(os.path.join(self.tempdir, "local-rpc"))
        os.mkdir(os.path.join(self.tempdir, "rpc"))
        os.mkdir(os.path.join(self.tempdir, "rpc-config"))
        self.addCleanup(shutil.rmtree, self.tempdir)

    def start_agent(self):
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = os.path.join(ROOT_PATH, "libqrexec")
        env["VCHAN_DOMAIN"] = str(self.domain)
        env["VCHAN_SOCKET_DIR"] = self.tempdir
        env["QREXEC_SERVICE_PATH"] = ":".join(
            [
                os.path.join(self.tempdir, "local-rpc"),
                os.path.join(self.tempdir, "rpc"),
            ]
        )
        env["QUBES_RPC_CONFIG_PATH"] = os.path.join(self.tempdir, "rpc-config")
        env["QREXEC_MULTIPLEXER_PATH"] = os.path.join(
            ROOT_PATH, "lib", "qubes-rpc-multiplexer"
        )
        cmd = [
            os.path.join(ROOT_PATH, "agent", "qrexec-agent"),
            "--no-fork-server",
            "--agent-socket=" + os.path.join(self.tempdir, "agent.sock"),
        ]
        if os.environ.get("USE_STRACE"):
            cmd = ["strace", "-fD"] + cmd
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
            self.tempdir, self.target_domain, self.domain, self.target_port
        )
        self.addCleanup(target.close)
        target.accept()
        return target

    def connect_client(self):
        client = qrexec.socket_client(os.path.join(self.tempdir, "agent.sock"))
        self.addCleanup(client.close)
        return client


@unittest.skipIf(os.environ.get("SKIP_SOCKET_TESTS"), "socket tests not set up")
class TestAgent(TestAgentBase):
    def test_handshake(self):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

    def test_just_exec(self):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

        user = getpass.getuser().encode("ascii")

        cmd = ("touch " + os.path.join(self.tempdir, "new_file")).encode(
            "ascii"
        )
        dom0.send_message(
            qrexec.MSG_JUST_EXEC,
            struct.pack("<LL", self.target_domain, self.target_port)
            + user
            + b":"
            + cmd
            + b"\0",
        )

        target = self.connect_target()
        target.handshake()
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

        util.wait_until(
            lambda: os.path.exists(os.path.join(self.tempdir, "new_file")),
            "file created",
        )

        self.assertEqual(
            dom0.recv_message(),
            (
                qrexec.MSG_CONNECTION_TERMINATED,
                struct.pack("<LL", self.target_domain, self.target_port),
            ),
        )

    def test_exec_cmdline(self):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

        user = getpass.getuser().encode("ascii")

        dom0.send_message(
            qrexec.MSG_EXEC_CMDLINE,
            struct.pack("<LL", self.target_domain, self.target_port)
            + user
            + b":echo Hello world\0",
        )

        target = self.connect_target()
        target.handshake()

        target.send_message(qrexec.MSG_DATA_STDIN, b"")

        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b"Hello world\n"),
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

        self.assertEqual(
            dom0.recv_message(),
            (
                qrexec.MSG_CONNECTION_TERMINATED,
                struct.pack("<LL", self.target_domain, self.target_port),
            ),
        )

    def test_trigger_service(self):
        self.start_agent()

        target_domain_name = b"target_domain"

        dom0 = self.connect_dom0()
        dom0.handshake()

        client = self.connect_client()
        ident = self.trigger_service(
            dom0, client, target_domain_name, b"qubes.ServiceName"
        )

        dom0.send_message(
            qrexec.MSG_SERVICE_CONNECT,
            struct.pack("<LL32s", self.target_domain, self.target_port, ident),
        )

        data = client.recvall(8)
        self.assertEqual(
            struct.unpack("<LL", data), (self.target_domain, self.target_port)
        )

        client.close()
        self.assertEqual(
            dom0.recv_message(),
            (
                qrexec.MSG_CONNECTION_TERMINATED,
                struct.pack("<LL", self.target_domain, self.target_port),
            ),
        )

    def test_trigger_service_refused(self):
        self.start_agent()

        target_domain_name = b"target_domain"

        dom0 = self.connect_dom0()
        dom0.handshake()

        client = self.connect_client()
        ident = self.trigger_service(
            dom0, client, target_domain_name, b"qubes.ServiceName"
        )

        dom0.send_message(
            qrexec.MSG_SERVICE_REFUSED, struct.pack("<32s", ident)
        )

        # agent should close connection to client
        data = client.recvall(8)
        self.assertEqual(data, b"")

    def trigger_service(self, dom0, client, target_domain_name, service_name):
        source_params = (
            struct.pack("<64s32s", target_domain_name, b"SOCKET")
            + service_name
            + b"\0"
        )

        client.send_message(
            qrexec.MSG_TRIGGER_SERVICE3,
            source_params,
        )

        message_type, target_params = dom0.recv_message()
        self.assertEqual(message_type, qrexec.MSG_TRIGGER_SERVICE3)

        ident = target_params[64:96]
        ident = ident[: ident.find(b"\0")]
        self.assertTrue(
            ident.startswith(b"SOCKET"), "wrong ident: {}".format(ident)
        )

        # The params should be the same except for ident.
        self.assertEqual(
            target_params,
            source_params[:64] + ident + source_params[64 + len(ident) :],
        )

        return ident


@unittest.skipIf(os.environ.get("SKIP_SOCKET_TESTS"), "socket tests not set up")
class TestAgentExecQubesRpc(TestAgentBase):
    def execute_qubesrpc(self, service: str, src_domain_name: str):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

        user = getpass.getuser()
        cmdline = "{}:QUBESRPC {} {}\0".format(
            user, service, src_domain_name
        ).encode("ascii")

        dom0.send_message(
            qrexec.MSG_EXEC_CMDLINE,
            struct.pack("<LL", self.target_domain, self.target_port) + cmdline,
        )

        target = self.connect_target()
        target.handshake()
        return target

    def make_executable_service(self, *args):
        util.make_executable_service(self.tempdir, *args)

    def test_exec_service(self):
        util.make_executable_service(
            self.tempdir,
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
echo "arg: $1, remote domain: $QREXEC_REMOTE_DOMAIN"
""",
        )
        target = self.execute_qubesrpc("qubes.Service+arg", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b"arg: arg, remote domain: domX\n"),
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_wait_for_session(self):
        log = os.path.join(self.tempdir, "wait-for-session.log")
        util.make_executable_service(
            self.tempdir,
            "rpc",
            "qubes.WaitForSession",
            """\
#!/bin/sh
read user
echo "wait for session: arg: $1, remote domain: $QREXEC_REMOTE_DOMAIN, user: $user" >{}
""".format(
                log
            ),
        )
        util.make_executable_service(
            self.tempdir,
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
cat {}
sleep 0.1
read input
echo "arg: $1, remote domain: $QREXEC_REMOTE_DOMAIN, input: $input"
""".format(
                log
            ),
        )
        with open(
            os.path.join(self.tempdir, "rpc-config", "qubes.Service+arg"), "w"
        ) as f:
            f.write("""\

# Test TOML file
wait-for-session = 1 # line comment
""")
        user = getpass.getuser()

        target = self.execute_qubesrpc("qubes.Service+arg", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"stdin data\n")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (
                    qrexec.MSG_DATA_STDOUT,
                    (
                        b"wait for session: arg: , remote domain: domX, user: "
                        + user.encode()
                        + b"\n"
                    ),
                ),
                (
                    qrexec.MSG_DATA_STDOUT,
                    b"arg: arg, remote domain: domX, input: stdin data\n",
                ),
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_exec_service_fail(self):
        target = self.execute_qubesrpc("qubes.Service+arg", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\177\0\0\0"),
            ],
        )

    def test_exec_service_with_arg(self):
        self.make_executable_service(
            "local-rpc",
            "qubes.Service+arg",
            """\
#!/bin/sh
echo "specific service"
""",
        )
        self.make_executable_service(
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
echo "general service"
""",
        )
        target = self.execute_qubesrpc("qubes.Service+arg", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b"specific service\n"),
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_connect_socket(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+arg"
        )
        server = qrexec.socket_server(socket_path)
        self.addCleanup(server.close)

        target = self.execute_qubesrpc("qubes.SocketService+arg", "domX")

        server.accept()
        expected = b"qubes.SocketService+arg domX\0"
        self.assertEqual(server.recvall(len(expected)), expected)

        message = b"stdin data"
        target.send_message(qrexec.MSG_DATA_STDIN, message)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertEqual(server.recvall(len(message)), message)

        server.sendall(b"stdout data")
        server.close()
        messages = target.recv_all_messages()
        # No stderr
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b"stdout data"),
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_service_close_stdout_stderr_early(self):
        self.make_executable_service(
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
read
echo closing stdout
exec >&-
read
echo closing stderr >&2
exec 2>&-
read code
exit $code
""",
        )
        target = self.execute_qubesrpc("qubes.Service", "domX")

        target.send_message(qrexec.MSG_DATA_STDIN, b"\n")

        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"closing stdout\n")
        )
        self.assertEqual(target.recv_message(), (qrexec.MSG_DATA_STDOUT, b""))

        target.send_message(qrexec.MSG_DATA_STDIN, b"\n")

        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDERR, b"closing stderr\n")
        )
        self.assertEqual(target.recv_message(), (qrexec.MSG_DATA_STDERR, b""))

        target.send_message(qrexec.MSG_DATA_STDIN, b"42\n")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertEqual(
            target.recv_message(),
            (qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)),
        )


@unittest.skipIf(os.environ.get("SKIP_SOCKET_TESTS"), "socket tests not set up")
class TestAgentStreams(TestAgentBase):
    def execute(self, cmd: str):
        self.start_agent()

        dom0 = self.connect_dom0()
        dom0.handshake()

        user = getpass.getuser()
        cmdline = "{}:{}\0".format(user, cmd).encode("ascii")

        dom0.send_message(
            qrexec.MSG_EXEC_CMDLINE,
            struct.pack("<LL", self.target_domain, self.target_port) + cmdline,
        )

        target = self.connect_target()
        target.handshake()
        return target

    def test_stdin_stderr(self):
        target = self.execute('echo "stdout"; echo "stderr" >&2')
        target.send_message(qrexec.MSG_DATA_STDIN, b"")

        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b"stdout\n"),
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b"stderr\n"),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_pass_stdin(self):
        target = self.execute("cat")

        target.send_message(qrexec.MSG_DATA_STDIN, b"data 1")
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"data 1")
        )

        target.send_message(qrexec.MSG_DATA_STDIN, b"data 2")
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"data 2")
        )

        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_close_stdin_early(self):
        # Make sure that we cover the error on writing stdin into living
        # process.
        target = self.execute(
            """
read
exec <&-
echo closed stdin
sleep 1
"""
        )
        target.send_message(qrexec.MSG_DATA_STDIN, b"data 1\n")
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"closed stdin\n")
        )
        target.send_message(qrexec.MSG_DATA_STDIN, b"data 2\n")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")

        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_buffer_stdin(self):
        # Test to trigger WRITE_STDIN_BUFFERED.

        # Values carefully selected to block stdin pipe but not block vchan.
        data_size = 256 * 1024
        data = bytes(
            itertools.islice(
                itertools.cycle(b"abcdefghijklmnopqrstuvwxyz"), data_size
            )
        )
        msg_size = 32 * 1024

        fifo = os.path.join(self.tempdir, "fifo")
        os.mkfifo(fifo)
        target = self.execute("read <{}; cat".format(fifo))

        for i in range(0, data_size, msg_size):
            msg = data[i : i + msg_size]
            target.send_message(qrexec.MSG_DATA_STDIN, msg)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")

        # Signal the process to start reading.
        with open(fifo, "a") as f:
            f.write("end\n")
            f.flush()

        messages = []
        received_data = b""
        while len(received_data) < data_size:
            message_type, message = target.recv_message()
            if message_type != qrexec.MSG_DATA_STDOUT:
                messages.append((message_type, message))
            else:
                self.assertEqual(message_type, qrexec.MSG_DATA_STDOUT)
                received_data += message

        self.assertEqual(len(received_data), data_size)
        self.assertEqual(received_data, data)

        messages += target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_close_stdout_stderr_early(self):
        target = self.execute(
            """\
read
echo closing stdout
exec >&-
read
echo closing stderr >&2
exec 2>&-
read code
exit $code
"""
        )

        target.send_message(qrexec.MSG_DATA_STDIN, b"\n")

        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"closing stdout\n")
        )
        self.assertEqual(target.recv_message(), (qrexec.MSG_DATA_STDOUT, b""))

        target.send_message(qrexec.MSG_DATA_STDIN, b"\n")

        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDERR, b"closing stderr\n")
        )
        self.assertEqual(target.recv_message(), (qrexec.MSG_DATA_STDERR, b""))

        target.send_message(qrexec.MSG_DATA_STDIN, b"42\n")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertEqual(
            target.recv_message(),
            (qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)),
        )

    def test_stdio_socket(self):
        target = self.execute(
            """\
kill -USR1 $QREXEC_AGENT_PID
echo hello world >&0
read x
echo "received: $x" >&0
"""
        )
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"hello world\n")
        )

        target.send_message(qrexec.MSG_DATA_STDIN, b"stdin\n")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")

        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b"received: stdin\n"),
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

    def test_exit_before_closing_streams(self):
        fifo = os.path.join(self.tempdir, "fifo")
        os.mkfifo(fifo)
        target = self.execute(
            """\
# duplicate original stdin to fd 3, because bash will
# close original stdin in child process
exec 3<&0

( read <&3; echo stdin closed; read <{fifo}; echo child exiting )&
echo process waiting
read <{fifo}
echo process exiting
exit 42
""".format(
                fifo=fifo
            )
        )
        self.assertEqual(
            target.recv_message(),
            (qrexec.MSG_DATA_STDOUT, b"process waiting\n"),
        )
        with open(fifo, "a") as f:
            f.write("1\n")
            f.flush()
        self.assertEqual(
            target.recv_message(),
            (qrexec.MSG_DATA_STDOUT, b"process exiting\n"),
        )
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"stdin closed\n")
        )
        with open(fifo, "a") as f:
            f.write("end\n")
            f.flush()
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"child exiting\n")
        )
        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)),
            ],
        )


@unittest.skipIf(os.environ.get("SKIP_SOCKET_TESTS"), "socket tests not set up")
class TestClientVm(unittest.TestCase):
    client = None
    domain = 42
    target_domain_name = "target_domain"
    target_domain = 43
    target_port = 1024

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempdir)

    def start_client(self, args):
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = os.path.join(ROOT_PATH, "libqrexec")
        env["VCHAN_DOMAIN"] = str(self.domain)
        env["VCHAN_SOCKET_DIR"] = self.tempdir
        env["QREXEC_NO_ROOT"] = "1"
        cmd = [
            os.path.join(ROOT_PATH, "agent", "qrexec-client-vm"),
            "--agent-socket=" + os.path.join(self.tempdir, "agent.sock"),
        ] + args
        stderr_dup = os.dup(sys.stderr.fileno())
        if os.environ.get("USE_STRACE"):
            cmd = ["strace", "-fD", "-o", "/proc/self/fd/%d" % stderr_dup] + cmd
        self.client = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(stderr_dup,),
        )
        os.close(stderr_dup)
        self.addCleanup(self.stop_client)

    def stop_client(self):
        if self.client and self.client.returncode is None:
            self.client.terminate()
            self.client.communicate()
            self.client = None

    def connect_server(self):
        server = qrexec.socket_server(os.path.join(self.tempdir, "agent.sock"))
        self.addCleanup(server.close)
        return server

    def connect_target_client(self):
        target_client = qrexec.vchan_client(
            self.tempdir, self.domain, self.target_domain, self.target_port
        )
        self.addCleanup(target_client.close)
        return target_client

    def run_service(self, *, local_program=None, options=None):
        server = self.connect_server()

        args = options or []
        args.append(self.target_domain_name)
        args.append("qubes.ServiceName")
        if local_program:
            args += local_program

        self.start_client(args)
        server.accept()

        message_type, data = server.recv_message()
        self.assertEqual(message_type, qrexec.MSG_TRIGGER_SERVICE3)
        self.assertEqual(
            data,
            struct.pack("<64s32s", self.target_domain_name.encode(), b"SOCKET")
            + b"qubes.ServiceName\0",
        )

        server.sendall(struct.pack("<LL", self.target_domain, self.target_port))

        target_client = self.connect_target_client()
        target_client.handshake()

        return target_client

    def test_run_client(self):
        target_client = self.run_service()
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"stdout data\n")
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        self.assertEqual(self.client.stdout.read(), b"stdout data\n")
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)
        )
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_run_client_replace_chars(self):
        target_client = self.run_service(options=["-t"])
        target_client.send_message(
            qrexec.MSG_DATA_STDOUT, b"hello\x00world\xFF"
        )
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        self.assertEqual(self.client.stdout.read(), b"hello_world_")
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)
        )
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_run_client_refused(self):
        server = self.connect_server()
        self.start_client([self.target_domain_name, "qubes.ServiceName"])
        server.accept()

        message_type, __data = server.recv_message()
        self.assertEqual(message_type, qrexec.MSG_TRIGGER_SERVICE3)

        server.conn.close()
        self.client.wait()
        self.assertEqual(self.client.stdout.read(), b"")
        self.assertEqual(self.client.stderr.read(), b"Request refused\n")
        self.assertEqual(self.client.returncode, 126)

    def test_run_client_failed(self):
        target_client = self.run_service()
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 127)
        )
        # there should be no MSG_DATA_EXIT_CODE from qrexec-client-vm
        # and also no MSG_DATA_STDIN after receiving MSG_DATA_EXIT_CODE
        self.assertListEqual(target_client.recv_all_messages(), [])
        self.assertEqual(self.client.stdout.read(), b"")
        self.client.wait()
        self.assertEqual(self.client.returncode, 127)

    def test_run_client_with_local_proc(self):
        target_client = self.run_service(local_program=["/bin/cat"])
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"stdout data\n")
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        self.assertEqual(
            target_client.recv_message(),
            (qrexec.MSG_DATA_STDIN, b"stdout data\n"),
        )
        self.assertEqual(
            target_client.recv_message(), (qrexec.MSG_DATA_STDIN, b"")
        )
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)
        )
        # there should be no MSG_DATA_EXIT_CODE from qrexec-client-vm
        self.assertListEqual(target_client.recv_all_messages(), [])
        self.assertEqual(self.client.stdout.read(), b"")
        self.assertEqual(self.client.stderr.read(), b"")
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_stdio_socket(self):
        target = self.run_service(
            local_program=[
                "/bin/sh",
                "-c",
                """\
kill -USR1 $QREXEC_AGENT_PID
echo hello world >&0
read x
echo "received: $x" >&0
""",
            ]
        )
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDIN, b"hello world\n")
        )

        target.send_message(qrexec.MSG_DATA_STDOUT, b"stdin\n")
        target.send_message(qrexec.MSG_DATA_STDOUT, b"")

        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDIN, b"received: stdin\n")
        )
        self.assertEqual(target.recv_message(), (qrexec.MSG_DATA_STDIN, b""))

        target.send_message(qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42))
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_run_client_with_local_proc_service_failed(self):
        target_client = self.run_service(local_program=["/bin/cat"])
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 127)
        )
        # there should be no MSG_DATA_EXIT_CODE from qrexec-client-vm
        self.assertListEqual(target_client.recv_all_messages(), [])
        target_client.close()
        self.assertEqual(self.client.stdout.read(), b"")
        self.client.wait()
        self.assertEqual(self.client.returncode, 127)

    def test_run_client_with_local_proc_local_proc_failed(self):
        target_client = self.run_service(local_program=["/bin/false"])
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 0)
        )
        # there should be no MSG_DATA_EXIT_CODE from qrexec-client-vm
        # empty MSG_DATA_STDIN (EOF) is permitted but not required
        messages_received = target_client.recv_all_messages()
        if messages_received:
            self.assertListEqual(messages_received, [(qrexec.MSG_DATA_STDIN, b"")])
        target_client.close()
        self.assertEqual(self.client.stdout.read(), b"")
        self.client.wait()

        # Client must exit with nonzero status (QubesOS/qubes-issues#7905),
        # otherwise qvm-move and qvm-move-to-vm will destroy user data if
        # qfile-agent fails.
        self.assertEqual(self.client.returncode, 1)

    def test_run_client_with_local_proc_refused(self):
        server = self.connect_server()
        flag_file = os.path.join(self.tempdir, "flag")
        self.start_client(
            [
                self.target_domain_name,
                "qubes.ServiceName",
                "/bin/touch",
                flag_file,
            ]
        )
        server.accept()

        message_type, data = server.recv_message()
        self.assertEqual(message_type, qrexec.MSG_TRIGGER_SERVICE3)
        self.assertEqual(
            data,
            struct.pack("<64s32s", self.target_domain_name.encode(), b"SOCKET")
            + b"qubes.ServiceName\0",
        )

        server.conn.close()
        self.client.wait()
        self.assertEqual(self.client.stdout.read(), b"")
        self.assertEqual(self.client.stderr.read(), b"Request refused\n")
        self.assertEqual(self.client.returncode, 126)
        self.assertFalse(os.path.exists(flag_file))

    def test_run_client_vchan_disconnect(self):
        target_client = self.run_service()
        self.client.stdin.write(b"stdin data\n")
        self.client.stdin.flush()
        self.assertEqual(
            target_client.recv_message(),
            (qrexec.MSG_DATA_STDIN, b"stdin data\n"),
        )
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"stdout data\n")
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        self.assertEqual(self.client.stdout.read(), b"stdout data\n")

        target_client.close()
        self.client.wait()
        self.assertEqual(self.client.returncode, 255)

    def test_run_client_with_local_proc_disconnect(self):
        target_client = self.run_service(local_program=["/bin/cat"])
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"stdout data\n")
        self.assertEqual(
            target_client.recv_message(),
            (qrexec.MSG_DATA_STDIN, b"stdout data\n"),
        )
        target_client.close()
        self.client.wait()
        self.assertEqual(self.client.returncode, 255)
