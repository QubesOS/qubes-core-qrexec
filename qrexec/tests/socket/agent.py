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
import socket
import shutil
import struct
import getpass
import itertools
import asyncio
import shlex

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

    def check_dom0(self, dom0):
        self.assertEqual(
            dom0.recv_message(),
            (
                qrexec.MSG_CONNECTION_TERMINATED,
                struct.pack("<LL", self.target_domain, self.target_port),
            ),
        )

    def assertExpectedStdout(self, target, expected_stdout: bytes, *, exit_code=0):
        messages = util.sort_messages(target.recv_all_messages())
        self.assertListEqual(messages[-3:],
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", exit_code))
            ])
        stdout_entries = []
        for msg_type, msg_body in messages[:-3]:
            # messages before last are not empty, hence truthy
            self.assertTrue(msg_body)
            self.assertEqual(msg_type, qrexec.MSG_DATA_STDOUT)
            stdout_entries.append(msg_body)
        self.assertEqual(b"".join(stdout_entries), expected_stdout)

    def make_executable_service(self, *args):
        util.make_executable_service(self.tempdir, *args)

    def setUp(self):
        self.agent = self.dom0 = None
        self.tempdir = tempfile.mkdtemp()
        os.mkdir(os.path.join(self.tempdir, "local-rpc"))
        os.mkdir(os.path.join(self.tempdir, "rpc"))
        os.mkdir(os.path.join(self.tempdir, "rpc-config"))
        self.addCleanup(shutil.rmtree, self.tempdir)

    def start_agent(self, fail_exec=False):
        if self.agent is not None:
            return
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = os.path.join(ROOT_PATH, "libqrexec")
        env["VCHAN_DOMAIN"] = str(self.domain)
        env["VCHAN_SOCKET_DIR"] = self.tempdir
        env["QREXEC_SERVICE_ARGUMENT"] = "%did_not_get_unset"
        env["QREXEC_REQUESTED_TARGET_KEYWORD"] = "%did_not_get_unset"
        env["QREXEC_REQUESTED_TARGET"] = "%did_not_get_unset"
        env["QREXEC_SERVICE_PATH"] = ":".join(
            [
                os.path.join(self.tempdir, "local-rpc"),
                os.path.join(self.tempdir, "rpc"),
            ]
        )
        env["QUBES_RPC_CONFIG_PATH"] = os.path.join(self.tempdir, "rpc-config")
        env["QREXEC_MULTIPLEXER_PATH"] = "/dev/null" if fail_exec else os.path.join(
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
        if self.dom0 is not None:
            return self.dom0
        dom0 = self.dom0 = qrexec.vchan_client(self.tempdir, self.domain, 0, 512)
        self.addCleanup(dom0.close)
        dom0.handshake()
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

    def _test_just_exec(self, cmd):
        self.start_agent()

        dom0 = self.connect_dom0()

        user = getpass.getuser().encode("ascii")

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
        return target, dom0

    def test_just_exec_socket(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+"
        )
        server = qrexec.socket_server(socket_path)

        cmd = b"QUBESRPC qubes.SocketService a"
        target, dom0 = self._test_just_exec(cmd)
        server.accept()
        self.assertEqual(server.recvall(len(cmd)), cmd[9:] + b"\0")
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

        self.check_dom0(dom0)

    def test_just_exec(self):
        fifo = os.path.join(self.tempdir, "new_file")
        os.mkfifo(fifo, mode=0o600)
        cmd = ("echo a >> " + shlex.quote(fifo)).encode("ascii", "strict")
        target, dom0 = self._test_just_exec(cmd)
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )
        with open(fifo, "rb") as f:
            self.assertEqual(f.read(), b"a\n")
        self.check_dom0(dom0)

    def test_just_exec_rpc(self):
        fifo = os.path.join(self.tempdir, "new_file")
        os.mkfifo(fifo, mode=0o600)
        util.make_executable_service(
            self.tempdir,
            "rpc",
            "qubes.Service",
            fr"""#!/bin/bash -eu
printf %s\\n "$QREXEC_SERVICE_FULL_NAME" >> {shlex.quote(fifo)}
""",
        )
        cmd = b"QUBESRPC qubes.Service+ domX"
        target, dom0 = self._test_just_exec(cmd)
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ],
        )

        with open(fifo, "rb") as f:
            self.assertEqual(f.read(), b"qubes.Service+\n")
        self.check_dom0(dom0)

    def test_just_exec_rpc_not_found(self):
        cmd = b"QUBESRPC qubes.Service+ domX"
        target, dom0 = self._test_just_exec(cmd)
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_EXIT_CODE, b"\177\0\0\0"),
            ],
        )
        self.check_dom0(dom0)

    def test_exec_cmdline(self):
        self.start_agent()

        dom0 = self.connect_dom0()

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

        self.assertExpectedStdout(target, b"Hello world\n")
        self.check_dom0(dom0)

    def test_trigger_service(self):
        self.start_agent()

        target_domain_name = b"target_domain"

        dom0 = self.connect_dom0()

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
        self.check_dom0(dom0)

    def test_trigger_service_refused(self):
        self.start_agent()

        target_domain_name = b"target_domain"

        dom0 = self.connect_dom0()

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
    def execute_qubesrpc(self, service: str, src_domain_name: str, fail_exec:bool=False):
        self.start_agent(fail_exec)

        dom0 = self.connect_dom0()

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
        return target, dom0

    def test_exec_symlink(self):
        util.make_executable_service(
            self.tempdir,
            "rpc",
            ".qubes.Service",
            """\
#!/bin/sh
echo "arg: $1, remote domain: $QREXEC_REMOTE_DOMAIN"
""",
        )
        os.symlink(".qubes.Service", os.path.join(self.tempdir, "rpc/qubes.Service"))
        target, dom0 = self.execute_qubesrpc("qubes.Service+arg", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertExpectedStdout(target, b"arg: arg, remote domain: domX\n")
        self.check_dom0(dom0)

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
        target, dom0 = self.execute_qubesrpc("qubes.Service+arg", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertExpectedStdout(target, b"arg: arg, remote domain: domX\n")
        self.check_dom0(dom0)

    def test_exec_service_keyword(self):
        util.make_executable_service(
            self.tempdir,
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh -e
printf %s\\\\n "arg: ${1+bad}, remote domain: $QREXEC_REMOTE_DOMAIN" \
"target name: ${QREXEC_REQUESTED_TARGET-NONAME}" \
"target keyword: ${QREXEC_REQUESTED_TARGET_KEYWORD-NOKEYWORD}" \
${QREXEC_REQUESTED_TARGET_TYPE+"target type: '${QREXEC_REQUESTED_TARGET_TYPE}'"} \
${QREXEC_SERVICE_ARGUMENT+"call argument: '${QREXEC_SERVICE_ARGUMENT}'"}
""",
        )
        target, dom0 = self.execute_qubesrpc("qubes.Service", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertExpectedStdout(target, b"""arg: , remote domain: domX
target name: NONAME
target keyword: NOKEYWORD
target type: ''
""")
        self.check_dom0(dom0)

    def test_exec_service_with_config(self):
        util.make_executable_service(
            self.tempdir,
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
echo "arg: $1, remote domain: $QREXEC_REMOTE_DOMAIN"
""",
        )
        with open(
            os.path.join(self.tempdir, "rpc-config", "qubes.Service+arg"), "w"
        ) as f:
            f.write("""\
wait-for-session = 0
# should be ignored for executable service
exit-on-service-eof = true
exit-on-client-eof = true
skip-service-descriptor = true
""")
        target, dom0 = self.execute_qubesrpc("qubes.Service+arg", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertExpectedStdout(target, b"arg: arg, remote domain: domX\n")
        self.check_dom0(dom0)

    def test_wait_for_session(self):
        self._test_wait_for_session("qubes.Service+arg")
    def test_wait_for_session_huge_path(self):
        l = 255 - len("qubes.Service+")
        arg = l * "a"
        self._test_wait_for_session("qubes.Service", argument=arg)
    def test_wait_for_session_config_in_location_sans_argument(self):
        self._test_wait_for_session("qubes.Service")
    def _test_wait_for_session(self, config_name, service_name="qubes.Service", argument="arg"):
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
            service_name,
            """\
#!/bin/sh
cat {}
read input
echo "arg: $1, remote domain: $QREXEC_REMOTE_DOMAIN, input: $input"
""".format(
                log
            ),
        )
        user = getpass.getuser()
        assert "'" not in user
        assert "\n" not in user
        with open(
            os.path.join(self.tempdir, "rpc-config", config_name), "w"
        ) as f:
            f.write(f"""\

# Test TOML file
force-user = '{user}'
wait-for-session = 1 # line comment
""")

        target, dom0 = self.execute_qubesrpc(service_name + "+" + argument, "domX")
        self.assertEqual(target.recv_message(), (
            qrexec.MSG_DATA_STDOUT,
            (
                b"wait for session: arg: , remote domain: domX, user: "
                + user.encode("ascii", "strict")
                + b"\n"
            ),
        ))
        target.send_message(qrexec.MSG_DATA_STDIN, b"stdin data\n")
        # Do not send EOF. Shell read doesn't need it, and this checks that
        # qrexec does not wait for EOF on stdin before sending the exit code
        # from the remote process.
        expected_stdout = (b"arg: " + argument.encode("ascii", "strict")
                           + b", remote domain: domX, input: stdin data\n")
        self.assertExpectedStdout(target, expected_stdout)
        self.check_dom0(dom0)

    def test_exec_service_not_found(self):
        """
        Service does not exist
        """
        self._test_exec_service_fail(qrexec.QREXEC_EXIT_SERVICE_NOT_FOUND)

    def test_exec_service_bad_multiplexer(self):
        """
        RPC multiplexer is junk
        """
        util.make_executable_service(self.tempdir, "rpc", "qubes.Service", "")
        target, dom0 = self.execute_qubesrpc("qubes.Service+arg", "domX", fail_exec=True)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        messages = util.sort_messages(target.recv_all_messages())
        self.assertEqual(messages[0], (qrexec.MSG_DATA_STDOUT, b""))
        self.assertListEqual(messages[-2:],
                             [
                                 (qrexec.MSG_DATA_STDERR, b""),
                                 (qrexec.MSG_DATA_EXIT_CODE, b"\175\0\0\0"),
                             ])
        for msg_type, msg_value in messages[1:-2]:
            self.assertEqual(msg_type, qrexec.MSG_DATA_STDERR)
            self.assertTrue(msg_value)
        self.check_dom0(dom0)

    def _test_exec_service_fail(self, exit_code=qrexec.QREXEC_EXIT_PROBLEM):
        target, dom0 = self.execute_qubesrpc("qubes.Service+arg", "domX")
        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", exit_code)),
            ],
        )
        self.check_dom0(dom0)

    def exec_service_with_invalid_config(self, invalid_config):
        util.make_executable_service(
            self.tempdir,
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
echo "arg: $1, remote domain: $QREXEC_REMOTE_DOMAIN"
""",
        )
        config_path = os.path.join(self.tempdir, "rpc-config", "qubes.Service+arg")
        if invalid_config is not None:
            with open(config_path, "w") as f:
                f.write(invalid_config)
        else:
            os.symlink("/dev/null/doesnotexist", config_path)
        self._test_exec_service_fail()

    def test_exec_service_with_invalid_config_path(self):
        util.make_executable_service(
            self.tempdir,
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
echo "arg: $1, remote domain: $QREXEC_REMOTE_DOMAIN"
""",
        )
        config_path = os.path.join(self.tempdir, "rpc-config")
        os.rmdir(config_path)
        os.symlink("/dev/null/doesnotexist", config_path)
        self._test_exec_service_fail()

    def test_exec_service_with_invalid_config_1(self):
        self.exec_service_with_invalid_config("wait-for-session = 00\n")

    def test_exec_service_with_invalid_config_2(self):
        self.exec_service_with_invalid_config("wait-for-session = 01\n")

    def test_exec_service_with_invalid_config_3(self):
        self.exec_service_with_invalid_config("wait-for-session = \n")

    def test_exec_service_with_invalid_config_4(self):
        self.exec_service_with_invalid_config("wait-for-session = \"a\"\n")

    def test_exec_service_with_invalid_config_5(self):
        self.exec_service_with_invalid_config("wait-for-session\n")

    def test_exec_service_with_invalid_config_6(self):
        self.exec_service_with_invalid_config(None)

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
        target, dom0 = self.execute_qubesrpc("qubes.Service+arg", "domX")
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
        self.check_dom0(dom0)

    def test_exec_broken_specific_service(self):
        os.symlink("/dev/null/invalid",
                   os.path.join(self.tempdir, "rpc", "qubes.Service+arg"))
        self.make_executable_service(
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
echo "general service"
""",
        )
        self._test_exec_service_fail()

    def test_exec_null_argument_finds_service_for_empty_argument(self):
        self.make_executable_service(
            "local-rpc",
            "qubes.Service+",
            """\
#!/bin/sh --
echo "specific service: $QREXEC_SERVICE_FULL_NAME"
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
        target, dom0 = self.execute_qubesrpc("qubes.Service", "domX")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertExpectedStdout(target, b"specific service: qubes.Service\n")
        self.check_dom0(dom0)

    def test_socket_null_argument_finds_service_for_empty_argument(self):
        good_socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+"
        )
        bad_socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        good_server = qrexec.socket_server(good_socket_path)
        self.addCleanup(good_server.close)
        bad_server = qrexec.socket_server(bad_socket_path)
        self.addCleanup(bad_server.close)

        target, dom0 = self.execute_qubesrpc("qubes.SocketService", "domX")

        good_server.accept()

        message = b"stdin data"
        target.send_message(qrexec.MSG_DATA_STDIN, message)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        expected = b"qubes.SocketService domX\0" + message
        self.assertEqual(good_server.recvall(len(expected)), expected)

        good_server.sendall(b"stdout data")
        good_server.close()
        self.assertExpectedStdout(target, b"stdout data")
        self.check_dom0(dom0)

    def _test_connect_socket_bad_config(self, forbidden_key):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+arg2"
        )
        user = getpass.getuser()
        with open(
            os.path.join(self.tempdir, "rpc-config", "qubes.SocketService+arg2"), "w"
        ) as f:
            f.write(f"""\
{forbidden_key} = true
force-user = '{user}'
""")
        server = qrexec.socket_server(socket_path)
        self.addCleanup(server.close)

        target, dom0 = self.execute_qubesrpc("qubes.SocketService+arg2", "domX")
        messages = target.recv_all_messages()
        self.assertListEqual(
            util.sort_messages(messages),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\175\0\0\0"),
            ],
        )
        self.check_dom0(dom0)
    def test_connect_socket_no_metadata_user(self):
        self._test_connect_socket_bad_config("skip-service-descriptor")
    def test_connect_socket_exit_on_stdin_eof_user(self):
        self._test_connect_socket_bad_config("exit-on-client-eof")
    def test_connect_socket_exit_on_stdout_eof_user(self):
        self._test_connect_socket_bad_config("exit-on-service-eof")

    def test_connect_socket_exit_on_stdin_eof(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+arg2"
        )
        with open(
            os.path.join(self.tempdir, "rpc-config", "qubes.SocketService+arg2"), "w"
        ) as f:
            f.write("""\
skip-service-descriptor = true
exit-on-client-eof = true
""")
        server = qrexec.socket_server(socket_path)
        self.addCleanup(server.close)

        target, dom0 = self.execute_qubesrpc("qubes.SocketService+arg2", "domX")

        server.accept()

        message = b"stdin data"
        target.send_message(qrexec.MSG_DATA_STDIN, message)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        # Check for EOF on stdin
        self.assertEqual(server.recvall(len(message) + 1), message)
        self.assertEqual(target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\0\0\0\0"),
            ])
        self.check_dom0(dom0)
        server.close()

    def test_connect_socket_exit_on_stdout_eof(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+arg2"
        )
        with open(
            os.path.join(self.tempdir, "rpc-config", "qubes.SocketService+arg2"), "w"
        ) as f:
            f.write("""\
skip-service-descriptor = true
exit-on-service-eof = true
""")
        server = qrexec.socket_server(socket_path)
        self.addCleanup(server.close)

        target, dom0 = self.execute_qubesrpc("qubes.SocketService+arg2", "domX")

        server.accept()

        message = b"stdin data"
        target.send_message(qrexec.MSG_DATA_STDIN, message)
        self.assertEqual(server.recvall(len(message)), message)
        # Trigger EOF on stdout
        server.shutdown(socket.SHUT_WR)
        # Server should exit
        self.assertExpectedStdout(target, b"")
        self.check_dom0(dom0)
        server.close()

    def test_connect_socket_no_metadata(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+arg2"
        )
        with open(
            os.path.join(self.tempdir, "rpc-config", "qubes.SocketService+arg2"), "w"
        ) as f:
            f.write("""\
skip-service-descriptor = true
""")
        server = qrexec.socket_server(socket_path)
        self.addCleanup(server.close)

        target, dom0 = self.execute_qubesrpc("qubes.SocketService+arg2", "domX")

        server.accept()

        message = b"stdin data"
        target.send_message(qrexec.MSG_DATA_STDIN, message)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertEqual(server.recvall(len(message)), message)

        server.sendall(b"stdout data")
        server.close()
        self.assertExpectedStdout(target, b"stdout data")
        self.check_dom0(dom0)

    def test_connect_socket_tcp(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+"
        )
        port = 65534
        host = "127.0.0.1"
        os.symlink(f"/dev/tcp/{host}/{port}", socket_path)
        self._test_tcp(socket.AF_INET, "qubes.SocketService", host, port)

    def _test_tcp_raw(self, family: int, service: str, host: str, port: int, accept=True, skip=True):
        server = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server = qrexec.QrexecServer(server)
        self.addCleanup(server.close)
        if skip:
            with open(os.path.join(self.tempdir, "rpc-config", service), "wb") as config:
                config.write(b"skip-service-descriptor = true\n")
                config.flush()
        target, dom0 = self.execute_qubesrpc(service, "domX")
        if accept:
            server.accept()
        message = b"stdin data"
        target.send_message(qrexec.MSG_DATA_STDIN, message)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        if accept:
            if not skip:
                message = b" domX\0".join((service.encode("ascii", "strict"), message))
            self.assertEqual(server.recvall(len(message)), message)
            server.sendall(b"stdout data")
        server.close()
        self.check_dom0(dom0)
        return target

    def _test_tcp(self, family: int, service: str, host: str, port: int) -> None:
        self.assertExpectedStdout(
            self._test_tcp_raw(family, service, host, port),
            b"stdout data")

    def test_connect_socket_tcp_port_from_arg(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        port = 65533
        host = "127.0.0.1"
        os.symlink(f"/dev/tcp/{host}", socket_path)
        self._test_tcp(socket.AF_INET, f"qubes.SocketService+{port}", host, port)

    def test_connect_socket_tcp_host_and_port_from_arg(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        port = 65535
        host = "127.0.0.1"
        os.symlink(f"/dev/tcp", socket_path)
        self._test_tcp(socket.AF_INET, f"qubes.SocketService+{host}+{port}", host, port)

    def test_connect_socket_tcp_ipv6(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        port = 65532
        host = "::1"
        os.symlink(f"/dev/tcp", socket_path)
        self._test_tcp(socket.AF_INET6, f"qubes.SocketService+{host.replace(':', '+')}+{port}", host, port)

    def test_connect_socket_tcp_ipv6_service_arg(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        port = 65532
        host = "::1"
        os.symlink(f"/dev/tcp", socket_path)
        service = f"qubes.SocketService+{host.replace(':', '+')}+{port}"
        self.assertExpectedStdout(
            self._test_tcp_raw(socket.AF_INET6, service, host, port, skip=False),
            b"stdout data",
        )

    def _test_connect_socket_tcp_unexpected_host(self, host):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        port = 65535
        path = f"/dev/tcp/{host}"
        os.symlink(path, socket_path)
        target = self._test_tcp_raw(socket.AF_INET, f"qubes.SocketService+{host}+{port}",
                                      host, port, accept=False)
        self.assertExpectedStdout(target, b"", exit_code=125)

    def test_connect_socket_tcp_missing_host(self):
        """
        /dev/tcp socket service, neither host nor port provided.
        """
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        path = "/dev/tcp"
        os.symlink(path, socket_path)
        target, dom0 = self.execute_qubesrpc("qubes.SocketService+", "domX")
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\175\0\0\0"),
            ],
        )
        self.check_dom0(dom0)

    def test_connect_socket_tcp_missing_port(self):
        """
        /dev/tcp socket service, host but not port provided.
        """
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        path = f"/dev/tcp"
        os.symlink(path, socket_path)
        target, dom0 = self.execute_qubesrpc("qubes.SocketService+127.0.0.1", "domX")
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\175\0\0\0"),
            ],
        )
        self.check_dom0(dom0)

    def test_connect_socket_tcp_no_port(self):
        """
        /dev/tcp/127.0.0.1 socket service, no port provided
        """
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        path = "/dev/tcp/127.0.0.1"
        os.symlink(path, socket_path)
        target, dom0 = self.execute_qubesrpc("qubes.SocketService", "domX")
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\175\0\0\0"),
            ],
        )
        self.check_dom0(dom0)

    def test_connect_socket_tcp_no_port_ipv6(self):
        """
        /dev/tcp/::1 socket service, no port provided
        """
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService"
        )
        path = "/dev/tcp/::1"
        os.symlink(path, socket_path)
        target, dom0 = self.execute_qubesrpc("qubes.SocketService", "domX")
        self.assertListEqual(
            target.recv_all_messages(),
            [
                (qrexec.MSG_DATA_STDOUT, b""),
                (qrexec.MSG_DATA_STDERR, b""),
                (qrexec.MSG_DATA_EXIT_CODE, b"\175\0\0\0"),
            ],
        )
        self.check_dom0(dom0)

    def test_connect_socket_tcp_unexpected_host(self):
        self._test_connect_socket_tcp_unexpected_host("127.0.0.1")

    def test_connect_socket_tcp_empty_host(self):
        self._test_connect_socket_tcp_unexpected_host("")

    def test_connect_socket(self):
        socket_path = os.path.join(
            self.tempdir, "rpc", "qubes.SocketService+arg"
        )
        server = qrexec.socket_server(socket_path)
        self.addCleanup(server.close)

        target, dom0 = self.execute_qubesrpc("qubes.SocketService+arg", "domX")

        server.accept()
        expected = b"qubes.SocketService+arg domX\0"
        self.assertEqual(server.recvall(len(expected)), expected)

        message = b"stdin data"
        target.send_message(qrexec.MSG_DATA_STDIN, message)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertEqual(server.recvall(len(message)), message)

        server.sendall(b"stdout data")
        server.close()
        self.assertExpectedStdout(target, b"stdout data")
        self.check_dom0(dom0)

    def test_service_close_stdout_stderr_early(self):
        self.make_executable_service(
            "rpc",
            "qubes.Service",
            """\
#!/bin/sh
read
echo closing stdout
exec >/dev/null
read
echo closing stderr >&2
exec 2>/dev/null
read code
exit $code
""",
        )
        target, dom0 = self.execute_qubesrpc("qubes.Service", "domX")

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
        self.check_dom0(dom0)


@unittest.skipIf(os.environ.get("SKIP_SOCKET_TESTS"), "socket tests not set up")
class TestAgentStreams(TestAgentBase):
    def execute(self, cmd: str):
        self.start_agent()

        dom0 = self.connect_dom0()

        user = getpass.getuser()
        cmdline = "{}:{}\0".format(user, cmd).encode("ascii")

        dom0.send_message(
            qrexec.MSG_EXEC_CMDLINE,
            struct.pack("<LL", self.target_domain, self.target_port) + cmdline,
        )

        target = self.connect_target()
        target.handshake()
        return target, dom0

    def test_stdin_stderr(self):
        target, dom0 = self.execute('echo "stdout"; echo "stderr" >&2')
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
        target, dom0 = self.execute("cat")

        target.send_message(qrexec.MSG_DATA_STDIN, b"data 1")
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"data 1")
        )

        target.send_message(qrexec.MSG_DATA_STDIN, b"data 2")
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"data 2")
        )

        target.send_message(qrexec.MSG_DATA_STDIN, b"")
        self.assertExpectedStdout(target, b"")

    def test_close_stdin_early(self):
        # Make sure that we cover the error on writing stdin into living
        # process.
        target, dom0 = self.execute(
            """
read
exec </dev/null
echo "closed stdin"
sleep 1
"""
        )
        target.send_message(qrexec.MSG_DATA_STDIN, b"data 1\n")
        self.assertEqual(
            target.recv_message(), (qrexec.MSG_DATA_STDOUT, b"closed stdin\n")
        )
        target.send_message(qrexec.MSG_DATA_STDIN, b"data 2\n")
        target.send_message(qrexec.MSG_DATA_STDIN, b"")

        self.assertExpectedStdout(target, b"")
        self.check_dom0(dom0)

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
        target, dom0 = self.execute("read <{}; cat".format(fifo))

        for i in range(0, data_size, msg_size):
            msg = data[i : i + msg_size]
            target.send_message(qrexec.MSG_DATA_STDIN, msg)
        target.send_message(qrexec.MSG_DATA_STDIN, b"")

        # Signal the process to start reading.
        with open(fifo, "a") as f:
            f.write("end\n")
            f.flush()
        self.assertExpectedStdout(target, data)
        self.check_dom0(dom0)

    def test_close_stdout_stderr_early(self):
        target, dom0 = self.execute(
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
        self.check_dom0(dom0)

    def test_stdio_socket(self):
        target, dom0 = self.execute(
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

        self.assertExpectedStdout(target, b"received: stdin\n")
        self.check_dom0(dom0)

    def test_exit_before_closing_streams(self):
        fifo = os.path.join(self.tempdir, "fifo")
        os.mkfifo(fifo)
        target, dom0 = self.execute(
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
        self.assertExpectedStdout(target, b"child exiting\n", exit_code=42)
        self.check_dom0(dom0)


@unittest.skipIf(os.environ.get("SKIP_SOCKET_TESTS"), "socket tests not set up")
class TestClientVm(unittest.TestCase):
    client = None
    domain = 42
    target_domain_name = "target_domain"
    target_domain = 43
    target_port = 1024

    def assertStdoutMessages(self, target, expected_stdout: bytes, ty=qrexec.MSG_DATA_STDOUT):
        bytes_recvd, expected = 0, len(expected_stdout)
        while bytes_recvd < expected:
            msg_type, msg_body = target.recv_message()
            self.assertEqual(msg_type, ty)
            l = len(msg_body)
            self.assertEqual(msg_body, expected_stdout[bytes_recvd:l])
            bytes_recvd += l
        self.assertEqual(bytes_recvd, expected)

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempdir)

    def start_client(self, args, stdio=subprocess.PIPE):
        if stdio is not subprocess.PIPE:
            self.assertIsInstance(stdio, socket.socket)
            args.insert(0, "--use-stdin-socket")
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
            stdin=stdio,
            stdout=stdio,
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

    def run_service(self, *, local_program=None, options=None, stdio=subprocess.PIPE):
        server = self.connect_server()

        args = options or []
        args.append(self.target_domain_name)
        args.append("qubes.ServiceName")
        if local_program:
            args += local_program

        self.start_client(args, stdio=stdio)
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

    def test_run_client_eof(self):
        remote, local = socket.socketpair()
        target_client = self.run_service(stdio=remote)
        remote.close()
        initial_data = b"stdout data\n"
        target_client.send_message(qrexec.MSG_DATA_STDOUT, initial_data)
        # FIXME: data can be received in multiple messages
        self.assertEqual(local.recv(len(initial_data)), initial_data)
        initial_data = b"stdin data\n"
        local.sendall(initial_data)
        self.assertStdoutMessages(target_client, initial_data, qrexec.MSG_DATA_STDIN)
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        # Check that EOF got propagated
        self.assertEqual(local.recv(1), b"")
        # Close local
        local.close()
        # Check that EOF got propagated on this side too
        self.assertEqual(target_client.recv_message(), (qrexec.MSG_DATA_STDIN, b""))
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)
        )
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_run_client_bidirectional_shutdown(self):
        try:
            remote, local = socket.socketpair()
            target_client = self.run_service(stdio=remote)
            initial_data = b"stdout data\n"
            target_client.send_message(qrexec.MSG_DATA_STDOUT, initial_data)
            # FIXME: data can be received in multiple messages
            self.assertEqual(local.recv(len(initial_data)), initial_data)
            initial_data = b"stdin data\n"
            local.sendall(initial_data)
            local.shutdown(socket.SHUT_WR)
            self.assertStdoutMessages(target_client, initial_data, qrexec.MSG_DATA_STDIN)
            # Check that EOF received
            self.assertEqual(target_client.recv_message(), (qrexec.MSG_DATA_STDIN, b""))
            target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
            # Check that EOF got propagated on this side too, even though
            # we still have a reference to the socket.  This indicates that
            # qrexec-client-vm shut down the socket for writing.
            self.assertEqual(local.recv(1), b"")
            with self.assertRaises(BrokenPipeError):
                remote.send(b"a")
            target_client.send_message(
                qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)
            )
            self.client.wait()
            self.assertEqual(self.client.returncode, 42)
        finally:
            remote.close()
            local.close()

    def test_run_client_bidirectional_shutdown_early_exit(self):
        try:
            remote, local = socket.socketpair()
            target_client = self.run_service(stdio=remote)
            initial_data = b"stdout data\n"
            target_client.send_message(qrexec.MSG_DATA_STDOUT, initial_data)
            # FIXME: data can be received in multiple messages
            self.assertEqual(local.recv(len(initial_data)), initial_data)
            initial_data = b"stdin data\n"
            local.sendall(initial_data)
            self.assertStdoutMessages(target_client, initial_data, qrexec.MSG_DATA_STDIN)
            target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
            # Check that EOF got propagated on this side too, even though
            # we still have a reference to the socket.  This indicates that
            # qrexec-client-vm shut down the socket for writing.
            self.assertEqual(local.recv(1), b"")
            with self.assertRaises(BrokenPipeError):
                remote.send(b"a")
            target_client.send_message(
                qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42)
            )
            local.shutdown(socket.SHUT_WR)
            # Check that EOF received
            self.assertEqual(target_client.recv_message(), (qrexec.MSG_DATA_STDIN, b""))
            self.client.wait()
            self.assertEqual(self.client.returncode, 42)
        finally:
            remote.close()
            local.close()


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
        self.assertEqual(self.client.returncode, qrexec.QREXEC_EXIT_REQUEST_REFUSED)

    def test_run_client_failed(self):
        target_client = self.run_service()
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", qrexec.QREXEC_EXIT_PROBLEM)
        )
        # there should be no MSG_DATA_EXIT_CODE from qrexec-client-vm
        # and also no MSG_DATA_STDIN after receiving MSG_DATA_EXIT_CODE
        self.assertListEqual(target_client.recv_all_messages(),
                             [(qrexec.MSG_DATA_STDIN, b"")])
        self.assertEqual(self.client.stdout.read(), b"")
        self.client.wait()
        self.assertEqual(self.client.returncode, qrexec.QREXEC_EXIT_PROBLEM)

    def test_run_client_with_local_proc(self):
        target_client = self.run_service(local_program=["/bin/cat"])
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"stdout data\n")
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        self.assertStdoutMessages(target_client, b"stdout data\n", qrexec.MSG_DATA_STDIN)
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
        self.assertStdoutMessages(target, b"hello world\n", qrexec.MSG_DATA_STDIN)

        target.send_message(qrexec.MSG_DATA_STDOUT, b"stdin\n")
        target.send_message(qrexec.MSG_DATA_STDOUT, b"")

        self.assertStdoutMessages(target, b"received: stdin\n", qrexec.MSG_DATA_STDIN)
        self.assertEqual(target.recv_message(), (qrexec.MSG_DATA_STDIN, b""))

        target.send_message(qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42))
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_stdio_socket_closed_stdin(self):
        fifo = os.path.join(self.tempdir, "new_file")
        os.mkfifo(fifo, mode=0o600)
        target = self.run_service(
            local_program=[
                "/bin/sh",
                "-euc",
                """\
echo hello world
# Wait for stdin to be closed for writing
read -r x
cat
# Request that stdin be used to send stdout data
kill -USR1 "$QREXEC_AGENT_PID"
echo "received: $x" >&0
# Avoid a race condition by ensuring the program does not exit too soon
read < "$1"
""",
                "sh",
                fifo,
            ]
        )
        self.assertStdoutMessages(target, b"hello world\n", qrexec.MSG_DATA_STDIN)

        target.send_message(qrexec.MSG_DATA_STDOUT, b"stdin\n")
        target.send_message(qrexec.MSG_DATA_STDOUT, b"")

        self.assertStdoutMessages(target, b"received: stdin\n", qrexec.MSG_DATA_STDIN)
        with open(fifo, "wb"): pass
        self.assertEqual(target.recv_message(), (qrexec.MSG_DATA_STDIN, b""))

        target.send_message(qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", 42))
        self.client.wait()
        self.assertEqual(self.client.returncode, 42)

    def test_run_client_with_local_proc_service_failed(self):
        target_client = self.run_service(local_program=["/bin/cat"])
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        target_client.send_message(
            qrexec.MSG_DATA_EXIT_CODE, struct.pack("<L", qrexec.QREXEC_EXIT_PROBLEM)
        )
        # there should be no MSG_DATA_EXIT_CODE from qrexec-client-vm
        self.assertListEqual(target_client.recv_all_messages(),
                             [(qrexec.MSG_DATA_STDIN, b"")])
        target_client.close()
        self.assertEqual(self.client.stdout.read(), b"")
        self.client.wait()
        self.assertEqual(self.client.returncode, qrexec.QREXEC_EXIT_PROBLEM)

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
        self.assertEqual(self.client.returncode, qrexec.QREXEC_EXIT_REQUEST_REFUSED)
        self.assertFalse(os.path.exists(flag_file))

    def test_run_client_vchan_disconnect(self):
        target_client = self.run_service()
        self.client.stdin.write(b"stdin data\n")
        self.client.stdin.flush()
        self.assertStdoutMessages(target_client, b"stdin data\n", qrexec.MSG_DATA_STDIN)
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"stdout data\n")
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"")
        self.assertEqual(self.client.stdout.read(), b"stdout data\n")

        target_client.close()
        self.client.wait()
        self.assertEqual(self.client.returncode, 255)

    def test_run_client_with_local_proc_disconnect(self):
        target_client = self.run_service(local_program=["/bin/cat"])
        target_client.send_message(qrexec.MSG_DATA_STDOUT, b"stdout data\n")
        self.assertStdoutMessages(target_client, b"stdout data\n", qrexec.MSG_DATA_STDIN)
        target_client.close()
        self.client.wait()
        self.assertEqual(self.client.returncode, 255)
