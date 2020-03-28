#!/usr/bin/python
#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2017 boring-stuff <boring-stuff@users.noreply.github.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <https://www.gnu.org/licenses/>.
#

# pylint:disable=protected-access

import sys
import unittest
import os

from qrexec.tests.gtkhelpers import GtkTestCase, FocusStealingHelperMock
from qrexec.tests.gtkhelpers import mock_domains_info, mock_whitelist

from qrexec.tools.qrexec_policy_agent import VMListModeler
from qrexec.tools.qrexec_policy_agent import RPCConfirmationWindow
from qrexec.tools.qrexec_policy_agent import escape_and_format_rpc_text


class MockRPCConfirmationWindow(RPCConfirmationWindow):
    def _new_vm_list_modeler(self):
        return VMListModeler(mock_domains_info)

    def _new_focus_stealing_helper(self):
        return FocusStealingHelperMock(
                    self._rpc_window,
                    self._rpc_ok_button,
                    self._focus_stealing_seconds)

    def __init__(self, source, service, argument, whitelist,
                 target=None, focus_stealing_seconds=1):
        # pylint: disable=too-many-arguments
        self._focus_stealing_seconds = focus_stealing_seconds

        RPCConfirmationWindow.__init__(
            self, mock_domains_info, source, service, argument, whitelist,
            target)

        self.test_called_close = False
        self.test_called_show = False

        self.test_clicked_ok = False
        self.test_clicked_cancel = False

    def _can_perform_action(self):
        return True

    def _close(self):
        self.test_called_close = True

    def _show(self):
        self.test_called_show = True

    async def _wait_for_close(self):
        pass

    def _clicked_ok(self, button):
        super()._clicked_ok(button)
        self.test_clicked_ok = True

    def _clicked_cancel(self, button):
        super()._clicked_cancel(button)
        self.test_clicked_cancel = True

    def is_error_visible(self):
        return self._error_bar.get_visible()

    def get_shown_domains(self):
        model = self._rpc_combo_box.get_model()
        model_iter = model.get_iter_first()
        domains = []

        while model_iter is not None:
            domain_name = model.get_value(model_iter, 1)

            domains += [domain_name]

            model_iter = model.iter_next(model_iter)

        return domains


@unittest.skipUnless(os.environ.get('DISPLAY'), 'no DISPLAY variable')
class RPCConfirmationWindowTestBase(GtkTestCase):
    def __init__(self, test_method, source_name="test-source",
                 service="test.Operation", argument="+", whitelist=mock_whitelist,
                 target_name=None):
        # pylint: disable=too-many-arguments
        GtkTestCase.__init__(self, test_method)
        self.test_source_name = source_name
        self.test_service = service
        self.test_argument = argument
        self.test_target_name = target_name

        self.whitelist = whitelist

        self._test_time = 0.1

    def setUp(self):
        self.window = MockRPCConfirmationWindow(
            self.test_source_name,
            self.test_service,
            self.test_argument,
            self.whitelist,
            self.test_target_name,
            focus_stealing_seconds=self._test_time)

    def test_has_linked_the_fields(self):
        self.assertIsNotNone(self.window._rpc_window)
        self.assertIsNotNone(self.window._rpc_ok_button)
        self.assertIsNotNone(self.window._rpc_cancel_button)
        self.assertIsNotNone(self.window._rpc_label)
        self.assertIsNotNone(self.window._source_entry)
        self.assertIsNotNone(self.window._rpc_combo_box)
        self.assertIsNotNone(self.window._error_bar)
        self.assertIsNotNone(self.window._error_message)

    def test_is_showing_source(self):
        self.assertTrue(self.test_source_name in self.window._source_entry.get_text())

    def test_is_showing_operation(self):
        self.assertTrue(self.test_service in self.window._rpc_label.get_text())

    def test_escape_and_format_rpc_text(self):
        # pylint: disable=no-self-use
        e = escape_and_format_rpc_text
        assert e('qubes.Test') == 'qubes.<b>Test</b>'
        assert e('custom.Domain') == 'custom.<b>Domain</b>'
        assert e('nodomain') == '<b>nodomain</b>'
        assert e('domain.Sub.Operation') == 'domain.<b>Sub.Operation</b>'
        assert e('') == '<b></b>'
        assert e('.') == '<b>.</b>'
        assert e('inject.<script>') == 'inject.<b>&lt;script&gt;</b>'
        assert e('<script>.inject') == '&lt;script&gt;.<b>inject</b>'

        assert e('qubes.Test', '') == 'qubes.<b>Test</b>'
        assert e('qubes.Test', '+') == 'qubes.<b>Test</b>'
        assert e('qubes.Test', '+arg') == 'qubes.<b>Test</b>+arg'

    async def test_lifecycle_open_select_ok(self):
        await self._lifecycle_start(select_target=True)
        self._lifecycle_click(click_type="ok")

    async def test_lifecycle_open_select_cancel(self):
        await self._lifecycle_start(select_target=True)
        self._lifecycle_click(click_type="cancel")

    async def test_lifecycle_open_select_exit(self):
        await self._lifecycle_start(select_target=True)
        self._lifecycle_click(click_type="exit")

    async def test_lifecycle_open_cancel(self):
        await self._lifecycle_start(select_target=False)
        self._lifecycle_click(click_type="cancel")

    async def test_lifecycle_open_exit(self):
        await self._lifecycle_start(select_target=False)
        self._lifecycle_click(click_type="exit")

    def _lifecycle_click(self, click_type):
        if click_type == "ok":
            self.window._rpc_ok_button.clicked()

            self.assertTrue(self.window.test_clicked_ok)
            self.assertFalse(self.window.test_clicked_cancel)
            self.assertTrue(self.window._confirmed)
            self.assertIsNotNone(self.window._target_name)
        elif click_type == "cancel":
            self.window._rpc_cancel_button.clicked()

            self.assertFalse(self.window.test_clicked_ok)
            self.assertTrue(self.window.test_clicked_cancel)
            self.assertFalse(self.window._confirmed)
        elif click_type == "exit":
            self.window._close()

            self.assertFalse(self.window.test_clicked_ok)
            self.assertFalse(self.window.test_clicked_cancel)
            self.assertIsNone(self.window._confirmed)

        self.assertTrue(self.window.test_called_close)


    async def _lifecycle_start(self, select_target):
        self.assertFalse(self.window.test_called_close)
        self.assertFalse(self.window.test_called_show)

        self.assert_initial_state(False)
        self.assertTrue(isinstance(self.window._focus_helper, FocusStealingHelperMock))

        # Need the following because of pylint's complaints
        if isinstance(self.window._focus_helper, FocusStealingHelperMock):
            FocusStealingHelperMock.simulate_focus(self.window._focus_helper)

        self.flush_gtk_events(self._test_time*2)
        self.assert_initial_state(True)

        # We expect the call to exit immediately, since no window is opened
        await self.window.confirm_rpc()

        self.assertFalse(self.window.test_called_close)
        self.assertTrue(self.window.test_called_show)

        self.assert_initial_state(True)

        if select_target:
            self.window._rpc_combo_box.set_active(1)

            self.assertTrue(self.window._rpc_ok_button.get_sensitive())

            self.assertIsNotNone(self.window._target_name)

        self.assertFalse(self.window.test_called_close)
        self.assertTrue(self.window.test_called_show)
        self.assertFalse(self.window.test_clicked_ok)
        self.assertFalse(self.window.test_clicked_cancel)
        self.assertFalse(self.window._confirmed)

    def assert_initial_state(self, after_focus_timer):
        self.assertIsNone(self.window._target_name)
        self.assertFalse(self.window.test_clicked_ok)
        self.assertFalse(self.window.test_clicked_cancel)
        self.assertFalse(self.window._confirmed)
        self.assertFalse(self.window._rpc_ok_button.get_sensitive())
        self.assertFalse(self.window._error_bar.get_visible())

        if after_focus_timer:
            self.assertTrue(self.window._focus_helper.can_perform_action())
        else:
            self.assertFalse(self.window._focus_helper.can_perform_action())


@unittest.skipUnless(os.environ.get('DISPLAY'), 'no DISPLAY variable')
class RPCConfirmationWindowTestWithTarget(RPCConfirmationWindowTestBase):
    def __init__(self, test_method):
        RPCConfirmationWindowTestBase.__init__(self, test_method,
                 source_name="test-source", service="test.Operation",
                 target_name="test-target")

    async def test_lifecycle_open_ok(self):
        await self._lifecycle_start(select_target=False)
        self._lifecycle_click(click_type="ok")

    def assert_initial_state(self, after_focus_timer):
        self.assertIsNotNone(self.window._target_name)
        self.assertFalse(self.window.test_clicked_ok)
        self.assertFalse(self.window.test_clicked_cancel)
        self.assertFalse(self.window._confirmed)
        if after_focus_timer:
            self.assertTrue(self.window._rpc_ok_button.get_sensitive())
            self.assertTrue(self.window._focus_helper.can_perform_action())
            self.assertEqual(self.window._target_name, 'test-target')
        else:
            self.assertFalse(self.window._rpc_ok_button.get_sensitive())
            self.assertFalse(self.window._focus_helper.can_perform_action())

    def _lifecycle_click(self, click_type):
        RPCConfirmationWindowTestBase._lifecycle_click(self, click_type)
        self.assertIsNotNone(self.window._target_name)


@unittest.skipUnless(os.environ.get('DISPLAY'), 'no DISPLAY variable')
class RPCConfirmationWindowTestWithDispVMTarget(RPCConfirmationWindowTestBase):
    def __init__(self, test_method):
        RPCConfirmationWindowTestBase.__init__(self, test_method,
                 source_name="test-source", service="test.Operation",
                 target_name="@dispvm:test-disp6")

    async def test_lifecycle_open_ok(self):
        await self._lifecycle_start(select_target=False)
        self._lifecycle_click(click_type="ok")

    def assert_initial_state(self, after_focus_timer):
        self.assertIsNotNone(self.window._target_name)
        self.assertFalse(self.window.test_clicked_ok)
        self.assertFalse(self.window.test_clicked_cancel)
        self.assertFalse(self.window._confirmed)
        if after_focus_timer:
            self.assertTrue(self.window._rpc_ok_button.get_sensitive())
            self.assertTrue(self.window._focus_helper.can_perform_action())
            self.assertEqual(self.window._target_name, '@dispvm:test-disp6')
        else:
            self.assertFalse(self.window._rpc_ok_button.get_sensitive())
            self.assertFalse(self.window._focus_helper.can_perform_action())


@unittest.skipUnless(os.environ.get('DISPLAY'), 'no DISPLAY variable')
class RPCConfirmationWindowTestWithTargetInvalid(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)

    def test_unknown(self):
        self.assert_raises_error(True, "test-source", "test-wrong-target")

    def test_empty(self):
        self.assert_raises_error(True, "test-source", "")

    def test_equals_source(self):
        self.assert_raises_error(True, "test-source", "test-source")

    def assert_raises_error(self, expect, source, target):
        rpcWindow = MockRPCConfirmationWindow(source, "test.Operation", "+",
                                              mock_whitelist, target=target)
        self.assertEquals(expect, rpcWindow.is_error_visible())


@unittest.skipUnless(os.environ.get('DISPLAY'), 'no DISPLAY variable')
class RPCConfirmationWindowTestWhitelist(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)

    def test_no_domains(self):
        self._assert_whitelist([], [])

    def test_all_red_domains(self):
        self._assert_whitelist(["test-red1", "test-red2", "test-red3"],
                               ["test-red1", "test-red2", "test-red3"])

    def test_all_red_domains_plus_nonexistent(self):
        self._assert_whitelist(
            ["test-red1", "test-red2", "test-red3",
             "test-blue1", "test-blue2", "test-blue3"],
            ["test-red1", "test-red2", "test-red3"])

    def test_all_allowed_domains(self):
        self._assert_whitelist(
            ["test-red1", "test-red2", "test-red3",
             "test-target", "@dispvm:test-disp6", "test-source", "dom0"],
            ["test-red1", "test-red2", "test-red3",
             "test-target", "Disposable VM (test-disp6)", "test-source",
                "dom0"])

    def _assert_whitelist(self, whitelist, expected):
        rpcWindow = MockRPCConfirmationWindow(
            "test-source", "test.Operation", "+", whitelist)

        domains = rpcWindow.get_shown_domains()

        self.assertCountEqual(domains, expected)

if __name__ == '__main__':
    test = False
    window = False

    if len(sys.argv) == 1 or sys.argv[1] == '-t':
        test = True
    elif sys.argv[1] == '-w':
        window = True
    else:
        print("Usage: " + __file__ + " [-t|-w]")

    if window:
        print(MockRPCConfirmationWindow("test-source",
                                        "qubes.Filecopy",
                                        "+",
                                        mock_whitelist,
                                        "test-red1").confirm_rpc())
    elif test:
        unittest.main(argv=[sys.argv[0]])
