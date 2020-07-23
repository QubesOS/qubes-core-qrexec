# -*- encoding: utf-8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2017 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
# Copyright (C) 2018-2019  Wojtek Porczyk <woju@invisiblethingslab.com>
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

import functools
import socket
import subprocess
import unittest.mock
import asyncio
import pytest

from .. import QREXEC_CLIENT, QUBESD_INTERNAL_SOCK
from .. import exc, utils
from ..policy import parser, parser_compat

SYSTEM_INFO = {
    'domains': {
        'dom0': {
            'tags': ['dom0-tag'],
            'type': 'AdminVM',
            'default_dispvm': 'default-dvm',
            'template_for_dispvms': False,
            'power_state': 'Running',
        },
        'test-vm1': {
            'tags': ['tag1', 'tag2'],
            'type': 'AppVM',
            'default_dispvm': 'default-dvm',
            'template_for_dispvms': False,
            'power_state': 'Running',
        },
        'test-vm2': {
            'tags': ['tag2'],
            'type': 'AppVM',
            'default_dispvm': 'default-dvm',
            'template_for_dispvms': False,
            'power_state': 'Running',
        },
        'test-vm3': {
            'tags': ['tag3'],
            'type': 'AppVM',
            'default_dispvm': 'default-dvm',
            'template_for_dispvms': True,
            'power_state': 'Halted',
        },
        'default-dvm': {
            'tags': [],
            'type': 'AppVM',
            'default_dispvm': 'default-dvm',
            'template_for_dispvms': True,
            'power_state': 'Halted',
        },
        'test-invalid-dvm': {
            'tags': ['tag1', 'tag2'],
            'type': 'AppVM',
            'default_dispvm': 'test-vm1',
            'template_for_dispvms': False,
            'power_state': 'Halted',
        },
        'test-no-dvm': {
            'tags': ['tag1', 'tag2'],
            'type': 'AppVM',
            'default_dispvm': None,
            'template_for_dispvms': False,
            'power_state': 'Halted',
        },
        'test-template': {
            'tags': ['tag1', 'tag2'],
            'type': 'TemplateVM',
            'default_dispvm': 'default-dvm',
            'template_for_dispvms': False,
            'power_state': 'Halted',
        },
        'test-standalone': {
            'tags': ['tag1', 'tag2'],
            'type': 'StandaloneVM',
            'default_dispvm': 'default-dvm',
            'template_for_dispvms': False,
            'power_state': 'Halted',
        },
    }
}

# a generic request helper
_req = functools.partial(parser.Request, 'test.Service', '+argument',
    system_info=SYSTEM_INFO)

# async mock
class AsyncMock(unittest.mock.MagicMock):
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)


class TC_00_VMToken(unittest.TestCase):
    def test_010_Source(self):
#       with self.assertRaises(exc.PolicySyntaxError):
#           parser.Source(None)
        parser.Source('test-vm1')
        parser.Source('@adminvm')
        parser.Source('dom0')
        parser.Source('@anyvm')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source('@default')
        parser.Source('@type:AppVM')
        parser.Source('@tag:tag1')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source('@dispvm')
        parser.Source('@dispvm:default-dvm')
        parser.Source('@dispvm:@tag:tag3')

        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source('@invalid')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source('@dispvm:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source('@dispvm:@tag:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source('@tag:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source('@type:')

    def test_020_Target(self):
        parser.Target('test-vm1')
        parser.Target('@adminvm')
        parser.Target('dom0')
        parser.Target('@anyvm')
        parser.Target('@default')
        parser.Target('@type:AppVM')
        parser.Target('@tag:tag1')
        parser.Target('@dispvm')
        parser.Target('@dispvm:default-dvm')
        parser.Target('@dispvm:@tag:tag3')

        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target('@invalid')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target('@dispvm:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target('@dispvm:@tag:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target('@tag:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target('@type:')

    def test_021_Target_expand(self):
        self.assertCountEqual(
            parser.Target('test-vm1').expand(system_info=SYSTEM_INFO),
            ['test-vm1'])
        self.assertCountEqual(
            parser.Target('@adminvm').expand(system_info=SYSTEM_INFO),
            ['@adminvm'])
        self.assertCountEqual(
            parser.Target('dom0').expand(system_info=SYSTEM_INFO),
            ['@adminvm'])
        self.assertCountEqual(
            parser.Target('@anyvm').expand(system_info=SYSTEM_INFO), [
                'test-vm1', 'test-vm2', 'test-vm3',
                '@dispvm:test-vm3',
                'default-dvm', '@dispvm:default-dvm', 'test-invalid-dvm',
                'test-no-dvm', 'test-template', 'test-standalone', '@dispvm'])
        self.assertCountEqual(
            parser.Target('@default').expand(system_info=SYSTEM_INFO),
            [])
        self.assertCountEqual(
            parser.Target('@type:AppVM').expand(system_info=SYSTEM_INFO), [
                'test-vm1', 'test-vm2', 'test-vm3',
                'default-dvm', 'test-invalid-dvm', 'test-no-dvm'])
        self.assertCountEqual(
            parser.Target('@type:TemplateVM').expand(system_info=SYSTEM_INFO),
            ['test-template'])
        self.assertCountEqual(
            parser.Target('@tag:tag1').expand(system_info=SYSTEM_INFO), [
                'test-vm1', 'test-invalid-dvm',
                'test-template', 'test-standalone', 'test-no-dvm'])
        self.assertCountEqual(
            parser.Target('@tag:tag2').expand(system_info=SYSTEM_INFO), [
                'test-vm1', 'test-vm2',
                'test-invalid-dvm', 'test-template', 'test-standalone',
                'test-no-dvm'])
        self.assertCountEqual(
            parser.Target('@tag:no-such-tag').expand(system_info=SYSTEM_INFO),
            [])
        self.assertCountEqual(
            parser.Target('@dispvm').expand(system_info=SYSTEM_INFO),
            ['@dispvm'])
        self.assertCountEqual(
            parser.Target('@dispvm:default-dvm').expand(system_info=SYSTEM_INFO),
            ['@dispvm:default-dvm'])

        # no DispVM from test-vm1 allowed
        self.assertCountEqual(
            parser.Target('@dispvm:test-vm1').expand(system_info=SYSTEM_INFO),
            [])

        self.assertCountEqual(
            parser.Target('@dispvm:test-vm3').expand(system_info=SYSTEM_INFO),
            ['@dispvm:test-vm3'])
        self.assertCountEqual(
            parser.Target('@dispvm:@tag:tag1').expand(system_info=SYSTEM_INFO),
            [])
        self.assertCountEqual(
            parser.Target('@dispvm:@tag:tag3').expand(system_info=SYSTEM_INFO),
            ['@dispvm:test-vm3'])

    def test_030_Redirect(self):
        self.assertIs(parser.Redirect(None), None)

        parser.Redirect('test-vm1')
        parser.Redirect('@adminvm')
        parser.Redirect('dom0')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@anyvm')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@default')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@type:AppVM')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@tag:tag1')
        parser.Redirect('@dispvm')
        parser.Redirect('@dispvm:default-dvm')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@dispvm:@tag:tag3')

        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@invalid')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@dispvm:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@dispvm:@tag:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@tag:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect('@type:')

    def test_040_IntendedTarget(self):
        parser.IntendedTarget('test-vm1')
        parser.IntendedTarget('@adminvm')
        parser.IntendedTarget('dom0')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@anyvm')
        parser.IntendedTarget('@default')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@type:AppVM')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@tag:tag1')
        parser.IntendedTarget('@dispvm')
        parser.IntendedTarget('@dispvm:default-dvm')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@dispvm:@tag:tag3')

        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@invalid')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@dispvm:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@dispvm:@tag:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@tag:')
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget('@type:')

    def test_100_match_single(self):
        self.assertTrue(parser.VMToken('@anyvm').match(
            parser.IntendedTarget('test-vm1').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@anyvm').match(
            parser.IntendedTarget('@default').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@default').match(
            parser.IntendedTarget('@default').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@tag:tag1').match(
            parser.IntendedTarget('test-vm1').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@type:AppVM').match(
            parser.IntendedTarget('test-vm1').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@type:TemplateVM').match(
            parser.IntendedTarget('test-template').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@anyvm').match(
            parser.IntendedTarget('@dispvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@anyvm').match(
            parser.IntendedTarget('@dispvm:default-dvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@dispvm').match(
            parser.IntendedTarget('@dispvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@dispvm:@tag:tag3').match(
            parser.IntendedTarget('@dispvm:test-vm3').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@adminvm').match(
            parser.IntendedTarget('@adminvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@adminvm').match(
            parser.IntendedTarget('dom0').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('dom0').match(
            parser.IntendedTarget('@adminvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('dom0').match(
            parser.IntendedTarget('dom0').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@dispvm:default-dvm').match(
            parser.IntendedTarget('@dispvm:default-dvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@anyvm').match(
            parser.IntendedTarget('@dispvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertTrue(parser.VMToken('@anyvm').match(
            parser.IntendedTarget('test-vm1').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))

        self.assertFalse(parser.VMToken('@default').match(
            parser.IntendedTarget('test-vm1').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@tag:tag1').match(
            parser.IntendedTarget('test-vm3').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))

        with self.assertRaises(exc.AccessDenied):
            parser.IntendedTarget('no-such-vm').verify(system_info=SYSTEM_INFO)

        # test-vm1.template_for_dispvms=False
        with self.assertRaises(exc.AccessDenied):
            parser.IntendedTarget('@dispvm:test-vm1').verify(
                system_info=SYSTEM_INFO)

        # test-vm3 has not tag1
        self.assertFalse(parser.VMToken('@dispvm:@tag:tag1').match(
            parser.IntendedTarget('@dispvm:test-vm3').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        # default-dvm has no tag3
        self.assertFalse(parser.VMToken('@dispvm:@tag:tag3').match(
            parser.IntendedTarget('@dispvm:default-dvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@anyvm').match(
            parser.IntendedTarget('dom0').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@anyvm').match(
            parser.IntendedTarget('@adminvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@tag:dom0-tag').match(
            parser.IntendedTarget('@adminvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@type:AdminVM').match(
            parser.IntendedTarget('@adminvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@tag:dom0-tag').match(
            parser.IntendedTarget('dom0').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@type:AdminVM').match(
            parser.IntendedTarget('dom0').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@tag:tag1').match(
            parser.IntendedTarget('dom0').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        with self.assertRaises(exc.AccessDenied):
            parser.IntendedTarget('@tag:tag1').verify(system_info=SYSTEM_INFO)
        with self.assertRaises(exc.AccessDenied):
            parser.IntendedTarget('@type:AppVM').verify(system_info=SYSTEM_INFO)
        with self.assertRaises(exc.AccessDenied):
            parser.IntendedTarget('@invalid').verify(system_info=SYSTEM_INFO)
        with self.assertRaises(exc.AccessDenied):
            parser.IntendedTarget('no-such-vm').verify(system_info=SYSTEM_INFO)
        self.assertFalse(parser.VMToken('@dispvm').match(
            parser.IntendedTarget('test-vm1').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@dispvm').match(
            parser.IntendedTarget('default-dvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        self.assertFalse(parser.VMToken('@dispvm:default-dvm').match(
            parser.IntendedTarget('default-dvm').verify(system_info=SYSTEM_INFO),
            system_info=SYSTEM_INFO))
        with self.assertRaises(exc.AccessDenied):
            parser.IntendedTarget('test-vm1\n').verify(system_info=SYSTEM_INFO)
        with self.assertRaises(exc.AccessDenied):
            parser.IntendedTarget('test-vm1  ').verify(system_info=SYSTEM_INFO)

class TC_01_Request(unittest.TestCase):
    def test_000_init(self):
        request = parser.Request(
            'qrexec.Service', '+argument', 'test-vm1', 'test-vm2',
            system_info=SYSTEM_INFO)
        self.assertEqual(request.service, 'qrexec.Service')
        self.assertEqual(request.argument, '+argument')
        self.assertEqual(request.source, 'test-vm1')
        self.assertEqual(request.target, 'test-vm2')
        self.assertEqual(request.system_info, SYSTEM_INFO)

    def test_001_invalid_argument(self):
        with self.assertRaises(AssertionError):
            parser.Request(
                'qrexec.Service', 'argument', 'test-vm1', '@type:AppVM',
                system_info=SYSTEM_INFO)

    def test_002_invalid_target(self):
        for invalid_target in ['no-such-vm', '@type:AppVM',
                '@dispvm:test-invalid-dvm', '@dispvm:test-vm1', #'@default',
                '@anyvm', '@tag:tag1', '@dispvm:@tag:tag1', '@invalid']:
            with self.subTest(invalid_target):
                with self.assertRaises(exc.AccessDenied):
                    parser.Request('qrexec.Service', '+argument', 'test-vm1',
                        invalid_target, system_info=SYSTEM_INFO)

#class TC_00_Rule(qubes.tests.QubesTestCase):
class TC_10_Rule(unittest.TestCase):
    def test_000_init(self):
        line = parser.Rule(
            'test.Service', '+argument', '@anyvm', '@anyvm', 'allow', (),
            policy=None, filepath='filename', lineno=12)

        self.assertEqual(line.service, 'test.Service')
        self.assertEqual(line.argument, '+argument')
        self.assertEqual(line.source, '@anyvm')
        self.assertIsInstance(line.source, parser.VMToken)
        self.assertEqual(line.target, '@anyvm')
        self.assertIsInstance(line.target, parser.VMToken)
        self.assertIsInstance(line.action, parser.Action.allow.value)

    def test_020_line_simple(self):
        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @anyvm ask',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, '@anyvm')
        self.assertEqual(line.target, '@anyvm')
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertIsNone(line.action.default_target)

    def test_021_line_simple(self):
        # also check spaces in action field
        line = parser.Rule.from_line(None,
            'test.Service +argument @tag:tag1 @type:AppVM ask target=test-vm2 user=user',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, '@tag:tag1')
        self.assertEqual(line.target, '@type:AppVM')
        self.assertEqual(line.action.target, 'test-vm2')
        self.assertEqual(line.action.user, 'user')
        self.assertIsNone(line.action.default_target)

    def test_022_line_simple(self):
        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @default allow target=@dispvm:test-vm2',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.allow.value)
        self.assertEqual(line.source, '@anyvm')
        self.assertEqual(line.target, '@default')
        self.assertEqual(line.action.target, '@dispvm:test-vm2')
        self.assertIsNone(line.action.user)
        with self.assertRaises(AttributeError):
            line.action.default_target

    def test_023_line_simple(self):
        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @default ask default_target=test-vm1',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, '@anyvm')
        self.assertEqual(line.target, '@default')
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, 'test-vm1')

    def test_024_line_simple(self):
        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @adminvm ask default_target=@adminvm',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, '@anyvm')
        self.assertEqual(line.target, '@adminvm')
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, '@adminvm')

    def test_030_line_invalid(self):
        invalid_lines = [
            'test.Service +argument @dispvm @default allow',  # @dispvm can't be a source
            'test.Service +argument @default @default allow',  # @default can't be a source
            'test.Service +argument @anyvm @default allow,target=@dispvm:@tag:tag1',  # @dispvm:@tag
            #  as override target
            'test.Service +argument @anyvm @default allow,target=@tag:tag1',  # @tag as override target
            'test.Service +argument @anyvm @default deny,target=test-vm1',  # target= used with deny
            'test.Service +argument @anyvm @anyvm deny,default_target=test-vm1',  # default_target=
            # with deny
            'test.Service +argument @anyvm @anyvm deny,user=user',  # user= with deny
            'test.Service +argument @anyvm @anyvm invalid',  # invalid action
            'test.Service +argument @anyvm @anyvm allow,invalid=xx',  # invalid option
            'test.Service +argument @anyvm @anyvm',  # missing action
            'test.Service +argument @anyvm @anyvm allow,default_target=test-vm1',  # default_target=
            #  with allow
            'test.Service +argument @invalid @anyvm allow',  # invalid source
            'test.Service +argument @anyvm @invalid deny',  # invalid target
            '',  # empty line
            'test.Service +argument @anyvm @anyvm allow extra',  # trailing words
            'test.Service +argument @anyvm @default allow',  # @default allow without target=

            'test.Service +argument @anyvm @anyvm allow notify',  # missing =yes/=no
            'test.Service +argument @anyvm @anyvm allow notify=xx',  # invalid notify

            '* +argument @anyvm @default allow', # specific argument for * service
        ]
        for line in invalid_lines:
            with self.subTest(line):
                with self.assertRaises(exc.PolicySyntaxError):
                    parser.Rule.from_line(None, line,
                        filepath='filename', lineno=12)

    def test_050_match(self):
        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @anyvm allow',
            filepath='filename', lineno=12)
        self.assertTrue(line.is_match(parser.Request(
            'test.Service', '+argument', 'test-vm1', 'test-vm2',
            system_info=SYSTEM_INFO)))

        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @anyvm allow',
            filepath='filename', lineno=12)
        self.assertTrue(line.is_match(parser.Request(
            'test.Service', '+argument', 'no-such-vm', 'test-vm2',
            system_info=SYSTEM_INFO)))

        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @dispvm allow',
            filepath='filename', lineno=12)
        self.assertTrue(line.is_match(parser.Request(
            'test.Service', '+argument', 'test-vm1', '@dispvm',
            system_info=SYSTEM_INFO)))

        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @dispvm allow',
            filepath='filename', lineno=12)
        self.assertFalse(line.is_match(parser.Request(
            'test.Service', '+argument', 'test-vm1', '@dispvm:default-dvm',
            system_info=SYSTEM_INFO)))

        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @dispvm:default-dvm allow',
            filepath='filename', lineno=12)
        self.assertTrue(line.is_match(parser.Request(
            'test.Service', '+argument', 'test-vm1', '@dispvm',
            system_info=SYSTEM_INFO)))

        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @dispvm:default-dvm allow',
            filepath='filename', lineno=12)
        self.assertTrue(line.is_match(parser.Request(
            'test.Service', '+argument', 'test-vm1', '@dispvm:default-dvm',
            system_info=SYSTEM_INFO)))

        line = parser.Rule.from_line(None,
            'test.Service +argument @anyvm @dispvm:@tag:tag3 allow',
            filepath='filename', lineno=12)
        self.assertTrue(line.is_match(parser.Request(
            'test.Service', '+argument', 'test-vm1', '@dispvm:test-vm3',
            system_info=SYSTEM_INFO)))

#   def test_070_expand_override_target(self):
#       line = parser.Rule.from_line(None,
#           'test.Service +argument @anyvm @anyvm allow target=test-vm2',
#           filepath='filename', lineno=12)
#       self.assertEqual(
#           line.action.target.resolve(SYSTEM_INFO, 'test-vm1'),
#           'test-vm2')

#   def test_071_expand_override_target_dispvm(self):
#       line = parser.Rule.from_line(
#           'test.Service +argument @anyvm @anyvm allow target=@dispvm',
#           filepath='filename', lineno=12)
#       self.assertEqual(
#           line.action.target.redirect(SYSTEM_INFO, 'test-vm1'),
#           '@dispvm:default-dvm')

#   def test_072_expand_override_target_dispvm_specific(self):
#       line = parser.Rule.from_line(
#           'test.Service +argument @anyvm @anyvm allow target=@dispvm:test-vm3',
#           filepath='filename', lineno=12)
#       self.assertEqual(
#           line.action.target.redirect(SYSTEM_INFO, 'test-vm1'),
#           '@dispvm:test-vm3')

#   def test_073_expand_override_target_dispvm_none(self):
#       line = parser.Rule.from_line(
#           'test.Service +argument @anyvm @anyvm allow target=@dispvm',
#           filepath='filename', lineno=12)
#       self.assertEqual(
#           line.action.target.redirect(SYSTEM_INFO, 'test-no-dvm'),
#           None)

#   def test_074_expand_override_target_dom0(self):
#       line = parser.Rule.from_line(
#           'test.Service +argument @anyvm @anyvm allow target=dom0',
#           filepath='filename', lineno=12)
#       self.assertEqual(
#           line.action.target.redirect(SYSTEM_INFO, 'test-no-dvm'),
#           '@adminvm')

#   def test_075_expand_override_target_dom0(self):
#       line = parser.Rule.from_line(
#           'test.Service +argument @anyvm @anyvm allow target=@adminvm',
#           filepath='filename', lineno=12)
#       self.assertEqual(
#           line.action.target.redirect(SYSTEM_INFO, 'test-no-dvm'),
#           '@adminvm')


@pytest.mark.parametrize('action_name,action,default', [
    ('deny', parser.Action.deny.value, True),
    ('ask', parser.Action.ask.value, False),
    ('allow', parser.Action.allow.value, False),
])
def test_line_notify(action_name, action, default):
    line = parser.Rule.from_line(
        None,
        'test.Service +argument @anyvm @adminvm {}'.format(action_name),
        filepath='filename', lineno=12)
    assert isinstance(line.action, action)
    assert line.action.notify is default

    line = parser.Rule.from_line(
        None,
        'test.Service +argument @anyvm @adminvm {} notify=yes'.format(action_name),
        filepath='filename', lineno=12)
    assert isinstance(line.action, action)
    assert line.action.notify is True

    line = parser.Rule.from_line(
        None,
        'test.Service +argument @anyvm @adminvm {} notify=no'.format(action_name),
        filepath='filename', lineno=12)
    assert isinstance(line.action, action)
    assert line.action.notify is False


@pytest.mark.parametrize('action_name,action', [
    ('ask', parser.Action.ask.value),
    ('allow', parser.Action.allow.value),
])
def test_line_autostart(action_name, action):
    line = parser.Rule.from_line(
        None,
        'test.Service +argument @anyvm @anyvm {}'.format(action_name),
        filepath='filename', lineno=12)
    assert isinstance(line.action, action)
    assert line.action.autostart is True

    line = parser.Rule.from_line(
        None,
        'test.Service +argument @anyvm @anyvm {} autostart=yes'.format(action_name),
        filepath='filename', lineno=12)
    assert isinstance(line.action, action)
    assert line.action.autostart is True

    line = parser.Rule.from_line(
        None,
        'test.Service +argument @anyvm @anyvm {} autostart=no'.format(action_name),
        filepath='filename', lineno=12)
    assert isinstance(line.action, action)
    assert line.action.autostart is False


class TC_11_Rule_service(unittest.TestCase):
    def test_020_line_simple(self):
        line = parser.Rule.from_line_service(None, 'test.Service', '+argument',
            '@anyvm @anyvm ask',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, '@anyvm')
        self.assertEqual(line.target, '@anyvm')
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
#       self.assertIsNone(line.default_target)

    def test_021_line_simple(self):
        # also check spaces in action field
        line = parser.Rule.from_line_service(None, 'test.Service', '+argument',
            '@tag:tag1 @type:AppVM ask target=test-vm2 user=user',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, '@tag:tag1')
        self.assertEqual(line.target, '@type:AppVM')
        self.assertEqual(line.action.target, 'test-vm2')
        self.assertEqual(line.action.user, 'user')
#       self.assertIsNone(line.default_target)

    def test_022_line_simple(self):
        line = parser.Rule.from_line_service(None, 'test.Service', '+argument',
            '@anyvm @default allow target=@dispvm:test-vm2',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.allow.value)
        self.assertEqual(line.source, '@anyvm')
        self.assertEqual(line.target, '@default')
        self.assertEqual(line.action.target, '@dispvm:test-vm2')
        self.assertIsNone(line.action.user)
#       self.assertIsNone(line.action.default)

    def test_023_line_simple(self):
        line = parser.Rule.from_line_service(None, 'test.Service', '+argument',
            '@anyvm @default ask default_target=test-vm1',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, '@anyvm')
        self.assertEqual(line.target, '@default')
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, 'test-vm1')

    def test_024_line_simple(self):
        line = parser.Rule.from_line_service(None, 'test.Service', '+argument',
            '@anyvm @adminvm ask default_target=@adminvm',
            filepath='filename', lineno=12)
        self.assertEqual(line.filepath, 'filename')
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, '@anyvm')
        self.assertEqual(line.target, '@adminvm')
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, '@adminvm')

    def test_030_line_invalid(self):
        invalid_lines = [
            '@dispvm @default allow',  # @dispvm can't be a source
            '@default @default allow',  # @default can't be a source
            '@anyvm @default allow,target=@dispvm:@tag:tag1',  # @dispvm:@tag
            #  as override target
            '@anyvm @default allow,target=@tag:tag1',  # @tag as override target
            '@anyvm @default deny,target=test-vm1',  # target= used with deny
            '@anyvm @anyvm deny,default_target=test-vm1',  # default_target=
            # with deny
            '@anyvm @anyvm deny,user=user',  # user= with deny
            '@anyvm @anyvm invalid',  # invalid action
            '@anyvm @anyvm allow,invalid=xx',  # invalid option
            '@anyvm @anyvm',  # missing action
            '@anyvm @anyvm allow,default_target=test-vm1',  # default_target=
            #  with allow
            '@invalid @anyvm allow',  # invalid source
            '@anyvm @invalid deny',  # invalid target
            '',  # empty line
            '@anyvm @anyvm allow extra',  # trailing words
            '@anyvm @default allow',  # @default allow without target=
        ]
        for line in invalid_lines:
            with self.subTest(line):
                with self.assertRaises(exc.PolicySyntaxError):
                    parser.Rule.from_line_service(None,
                        'test.Service', '+argument', line,
                        filepath='filename', lineno=12)

#class TC_20_Policy(qubes.tests.QubesTestCase):
class TC_20_Policy(unittest.TestCase):
    def test_000_load(self):
        policy = parser.TestPolicy(policy='''\
* * test-vm1 test-vm2 allow

# comment
* * test-vm2 test-vm3 ask
    # comment with trailing whitespace:    ''' '''
* * @anyvm @anyvm ask
''')

        self.assertEqual(len(policy.rules), 3)
        self.assertEqual(policy.rules[0].source, 'test-vm1')
        self.assertEqual(policy.rules[0].target, 'test-vm2')
        self.assertIsInstance(policy.rules[0].action, parser.Action.allow.value)

    def test_002_include(self):
        policy = parser.TestPolicy(policy={
            '__main__': '''\
                * * test-vm1 test-vm2 allow
                !include file2
                * * @anyvm @anyvm deny
            ''',
            'file2': '''\
                * * test-vm3 @default allow target=test-vm2
            ''',
        })

        self.assertEqual(len(policy.rules), 3)
        self.assertEqual(policy.rules[0].source, 'test-vm1')
        self.assertEqual(policy.rules[0].target, 'test-vm2')
        self.assertIsInstance(policy.rules[0].action, parser.Action.allow.value)
#       self.assertEqual(policy.rules[0].filename,
#           TMP_POLICY_DIR + '/test.service')
        self.assertEqual(policy.rules[0].lineno, 1)
        self.assertEqual(policy.rules[1].source, 'test-vm3')
        self.assertEqual(policy.rules[1].target, '@default')
        self.assertIsInstance(policy.rules[1].action, parser.Action.allow.value)
#       self.assertEqual(policy.rules[1].filename,
#           TMP_POLICY_DIR + '/test.service2')
        self.assertEqual(policy.rules[1].lineno, 1)
        self.assertEqual(policy.rules[2].source, '@anyvm')
        self.assertEqual(policy.rules[2].target, '@anyvm')
        self.assertIsInstance(policy.rules[2].action, parser.Action.deny.value)
#       self.assertEqual(policy.rules[2].filename,
#           TMP_POLICY_DIR + '/test.service')
        self.assertEqual(policy.rules[2].lineno, 3)

    def test_003_include_service(self):
        policy = parser.TestPolicy(policy={
            '__main__': '''\
                !include-service * * new-syntax
                !include-service * * old-syntax
            ''',
            'new-syntax': '''\
                test-vm2 test-vm3 ask
                # comment with whitespace  ''' '''
                @anyvm @dispvm ask default_target=@dispvm
            ''',
            'old-syntax': '''\
                test-vm2 test-vm3 ask
                # comment with whitespace  ''' '''
                $anyvm $dispvm ask,default_target=$dispvm
            ''',
            })
        self.assertEqual(len(policy.rules), 4)
        self.assertEqual(policy.rules[1].source, '@anyvm')
        self.assertEqual(policy.rules[1].target, '@dispvm')
        self.assertIsInstance(policy.rules[1].action,
            parser.Action.ask.value)
        self.assertEqual(policy.rules[1].action.default_target,
            '@dispvm')
        self.assertEqual(policy.rules[3].source, '@anyvm')
        self.assertEqual(policy.rules[3].target, '@dispvm')
        self.assertIsInstance(policy.rules[3].action,
            parser.Action.ask.value)
        self.assertEqual(policy.rules[3].action.default_target,
            '@dispvm')

    def test_010_find_rule(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm1 test-vm2 allow
            * * test-vm1 @anyvm ask
            * * test-vm2 @tag:tag1 deny
            * * test-vm2 @tag:tag2 allow
            * * test-vm2 @dispvm:@tag:tag3 allow
            * * test-vm2 @dispvm:@tag:tag2 allow
            * * test-vm2 @dispvm:default-dvm allow
            * * @type:AppVM @default allow target=test-vm3
            * * @tag:tag1 @type:AppVM allow
        ''')
        self.assertEqual(policy.rules[0],
            policy.find_matching_rule(_req('test-vm1', 'test-vm2')))
        self.assertEqual(policy.rules[1],
            policy.find_matching_rule(_req('test-vm1', 'test-vm3')))
        self.assertEqual(policy.rules[3],
            policy.find_matching_rule(_req('test-vm2', 'test-vm2')))
        self.assertEqual(policy.rules[2],
            policy.find_matching_rule(_req('test-vm2', 'test-no-dvm')))
        # @anyvm matches @default too
        self.assertEqual(policy.rules[1],
            policy.find_matching_rule(_req('test-vm1', '@default')))
        self.assertEqual(policy.rules[7],
            policy.find_matching_rule(_req('test-vm2', '@default')))
        self.assertEqual(policy.rules[8],
            policy.find_matching_rule(_req('test-no-dvm', 'test-vm3')))
        self.assertEqual(policy.rules[4],
            policy.find_matching_rule(_req('test-vm2', '@dispvm:test-vm3')))
        self.assertEqual(policy.rules[6],
            policy.find_matching_rule(_req('test-vm2', '@dispvm')))

        with self.assertRaises(exc.AccessDenied):
            policy.find_matching_rule(_req('test-no-dvm', 'test-standalone'))
        with self.assertRaises(exc.AccessDenied):
            policy.find_matching_rule(_req('test-no-dvm', '@dispvm'))
        with self.assertRaises(exc.AccessDenied):
            policy.find_matching_rule(_req('test-standalone', '@default'))

    def test_020_collect_targets_for_ask(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm1 test-vm2 allow
            * * test-vm1 @anyvm ask
            * * test-vm2 @tag:tag1 deny
            * * test-vm2 @tag:tag2 allow
            * * test-no-dvm @type:AppVM deny
            * * @type:AppVM @default allow target=test-vm3
            * * @tag:tag1 @type:AppVM allow
            * * test-no-dvm @dispvm allow
            * * test-standalone @dispvm allow
            * * test-standalone @adminvm allow
        ''')

        self.assertCountEqual(
            policy.collect_targets_for_ask(_req('test-vm1', '@default')),
            ['test-vm2', 'test-vm3',
                '@dispvm:test-vm3',
                'default-dvm', '@dispvm:default-dvm', 'test-invalid-dvm',
                'test-no-dvm', 'test-template', 'test-standalone'])
        self.assertCountEqual(
            policy.collect_targets_for_ask(_req('test-vm2', '@default')),
            ['test-vm3'])
        self.assertCountEqual(
            policy.collect_targets_for_ask(_req('test-vm3', '@default')),
            [])
        self.assertCountEqual(
            policy.collect_targets_for_ask(_req('test-standalone', '@default')),
            ['test-vm1', 'test-vm2', 'test-vm3',
                'default-dvm', 'test-no-dvm', 'test-invalid-dvm',
                '@dispvm:default-dvm', 'dom0'])
        self.assertCountEqual(
            policy.collect_targets_for_ask(_req('test-no-dvm', '@default')),
            [])


#class TC_10_PolicyAction(qubes.tests.QubesTestCase):
class TC_30_Resolution(unittest.TestCase):
    def setUp(self):
        self.request = parser.Request(
            'test.Service', '+argument', 'test-vm1', 'test-vm2',
            system_info=SYSTEM_INFO)

    #
    # allow
    #

    def test_000_allow_init(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm allow',
            filepath='filename', lineno=12)
        resolution = parser.AllowResolution(rule, self.request,
            user=None, target='test-vm2')
        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertIs(resolution.user, None)
        self.assertIs(resolution.target, 'test-vm2')
        self.assertFalse(resolution.notify)

    def test_001_allow_notify(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm allow notify=yes',
            filepath='filename', lineno=12)
        resolution = parser.AllowResolution(rule, self.request,
            user=None, target='test-vm2')
        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertIs(resolution.user, None)
        self.assertIs(resolution.target, 'test-vm2')
        self.assertTrue(resolution.notify)

    #
    # ask
    #

    def test_100_ask_init(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask',
            filepath='filename', lineno=12)
        resolution = parser.AskResolution(rule, self.request,
            user=None, targets_for_ask=['test-vm2'], default_target='test-vm2')

        with self.assertRaises(AttributeError):
            resolution.target

        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertIs(resolution.user, None)
        self.assertCountEqual(resolution.targets_for_ask, ['test-vm2'])
        self.assertFalse(resolution.notify)

    def test_101_ask_init(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask',
            filepath='filename', lineno=12)
        resolution = parser.AskResolution(rule, self.request,
            user=None, targets_for_ask=['test-vm2', 'test-vm3'],
            default_target='test-vm2')

        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertEqual(resolution.request.target, 'test-vm2')
        self.assertCountEqual(resolution.targets_for_ask,
            ['test-vm2', 'test-vm3'])
        self.assertIs(resolution.default_target, 'test-vm2')
        self.assertFalse(resolution.notify)

    def test_102_ask_notify(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask notify=yes',
            filepath='filename', lineno=12)
        resolution = parser.AskResolution(rule, self.request,
            user=None, targets_for_ask=['test-vm2'], default_target='test-vm2')

        with self.assertRaises(AttributeError):
            resolution.target

        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertIs(resolution.user, None)
        self.assertCountEqual(resolution.targets_for_ask, ['test-vm2'])
        self.assertTrue(resolution.notify)

    def test_103_ask_default_target_None(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask',
            filepath='filename', lineno=12)
        resolution = parser.AskResolution(rule, self.request,
            user=None, targets_for_ask=['test-vm2', 'test-vm3'],
            default_target=None)

        self.assertIsNone(resolution.default_target)

class TC_40_evaluate(unittest.TestCase):
    def setUp(self):
        self.policy = parser.TestPolicy(policy='''\
            * * test-vm1 test-vm2 allow
            * * test-vm1 @default allow target=test-vm2
            * * @tag:tag1 test-vm2 ask
            * * @tag:tag1 test-vm3 ask default_target=test-vm3
            * * @tag:tag2 @anyvm allow
            * * test-vm3 @anyvm deny''')

    def test_000_deny(self):
        policy = parser.TestPolicy(policy='''\
            * * @anyvm @anyvm deny''')
        with self.assertRaises(exc.AccessDenied) as e:
            policy.evaluate(_req('test-vm1', 'test-vm2'))
        self.assertTrue(e.exception.notify)

    def test_001_deny_no_notify(self):
        policy = parser.TestPolicy(policy='''\
            * * @anyvm @anyvm deny notify=no''')
        with self.assertRaises(exc.AccessDenied) as e:
            policy.evaluate(_req('test-vm1', 'test-vm2'))
        self.assertFalse(e.exception.notify)

    def test_030_eval_simple(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm1 test-vm2 allow''')

        request = _req('test-vm1', 'test-vm2')
        resolution = policy.evaluate(request)

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertIs(resolution.request, request)
        self.assertIs(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, 'test-vm2')

        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(_req('test-vm2', '@default'))

    def test_031_eval_default(self):
        resolution = self.policy.evaluate(_req('test-vm1', '@default'))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, self.policy.rules[1])
        self.assertEqual(resolution.target, 'test-vm2')
        self.assertEqual(resolution.request.target, '@default')

        with self.assertRaises(exc.AccessDenied):
            # action allow should hit, but no target specified (either by
            # caller or policy)
            self.policy.evaluate(_req('test-standalone', '@default'))

    def test_032_eval_no_autostart(self):
        # test-vm2 is running, test-vm3 is halted
        policy = parser.TestPolicy(policy='''\
            * * test-vm1 test-vm2 allow autostart=no
            * * test-vm1 test-vm3 allow autostart=no''')

        request = _req('test-vm1', 'test-vm2')
        resolution = policy.evaluate(request)
        self.assertIsInstance(resolution, parser.AllowResolution)

        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(_req('test-vm1', 'test-vm3'))

    def test_040_eval_ask(self):
        resolution = self.policy.evaluate(_req('test-standalone', 'test-vm2'))

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, self.policy.rules[2])
        self.assertEqual(resolution.request.target, 'test-vm2')
        self.assertCountEqual(resolution.targets_for_ask,
            ['test-vm1', 'test-vm2', 'test-vm3', '@dispvm:test-vm3',
                'default-dvm', '@dispvm:default-dvm', 'test-invalid-dvm',
                'test-no-dvm', 'test-template'])

    def test_041_eval_ask(self):
        resolution = self.policy.evaluate(_req('test-standalone', 'test-vm3'))

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, self.policy.rules[3])
        self.assertEqual(resolution.default_target, 'test-vm3')
        self.assertEqual(resolution.request.target, 'test-vm3')
        self.assertCountEqual(resolution.targets_for_ask,
            ['test-vm1', 'test-vm2', 'test-vm3', '@dispvm:test-vm3',
                'default-dvm', '@dispvm:default-dvm', 'test-invalid-dvm',
                'test-no-dvm', 'test-template'])

    def test_042_eval_ask_no_targets(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm3 @default ask''')
        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(_req('test-vm3', '@default'))

    def test_043_eval_ask_no_autostart(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm1 @anyvm ask''')
        resolution = policy.evaluate(_req('test-vm1', 'test-vm2'))
        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertCountEqual(resolution.targets_for_ask,
            ['test-standalone', 'test-vm2', 'test-vm3', '@dispvm:test-vm3',
             'default-dvm', '@dispvm:default-dvm', 'test-invalid-dvm',
             'test-no-dvm', 'test-template'])

        policy = parser.TestPolicy(policy='''\
            * * test-vm1 @anyvm ask autostart=no''')
        resolution = policy.evaluate(_req('test-vm1', 'test-vm2'))
        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertCountEqual(resolution.targets_for_ask,
            ['test-vm2'])

    def test_050_eval_resolve_dispvm(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm3 @dispvm allow''')
        resolution = policy.evaluate(_req('test-vm3', '@dispvm'))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, '@dispvm:default-dvm')
        self.assertEqual(resolution.request.target, '@dispvm')

    def test_051_eval_resolve_dispvm_fail(self):
        policy = parser.TestPolicy(policy='''\
            * * test-no-dvm @dispvm allow''')
        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(_req('test-no-dvm', '@dispvm'))

    def test_052_eval_invalid_override_target(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm3 @anyvm allow target=no-such-vm''')
        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(_req('test-vm3', '@default'))

    def test_053_eval_resolve_dispvm_from_any(self):
        policy = parser.TestPolicy(policy='''\
            * * @anyvm @dispvm allow''')
        resolution = policy.evaluate(_req('test-vm3', '@dispvm'))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, '@dispvm:default-dvm')
        self.assertEqual(resolution.request.target, '@dispvm')

    @unittest.expectedFailure
    def test_060_eval_to_dom0(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm3 @adminvm allow''')
        resolution = policy.evaluate(_req('test-vm3', 'dom0'))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, '@adminvm')
        self.assertEqual(resolution.request.target, 'dom0')

    def test_061_eval_to_dom0_keyword(self):
        policy = parser.TestPolicy(policy='''\
            * * test-vm3 @adminvm allow''')
        resolution = policy.evaluate(_req('test-vm3', '@adminvm'))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, '@adminvm')
        self.assertEqual(resolution.request.target, '@adminvm')

    def test_110_handle_user_response_allow(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask',
            filepath='filename', lineno=12)
        request = parser.Request('test.service', '+', 'test-vm1',
            'test-vm2', system_info=SYSTEM_INFO)
        resolution = parser.AskResolution(
            rule, request, user=None,
            targets_for_ask=['test-vm1', 'test-vm2'],
            default_target=None)
        resolution = resolution.handle_user_response(True, 'test-vm2')
        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.target, 'test-vm2')
        self.assertFalse(resolution.notify)

    def test_111_handle_user_response_allow_notify(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask notify=yes',
            filepath='filename', lineno=12)
        request = parser.Request('test.service', '+', 'test-vm1',
            'test-vm2', system_info=SYSTEM_INFO)
        resolution = parser.AskResolution(
            rule, request, user=None,
            targets_for_ask=['test-vm1', 'test-vm2'],
            default_target=None)
        resolution = resolution.handle_user_response(True, 'test-vm2')
        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.target, 'test-vm2')
        self.assertTrue(resolution.notify)

    def test_112_handle_user_response_deny_invalid(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask',
            filepath='filename', lineno=12)
        request = parser.Request('test.service', '+', 'test-vm1',
            'test-vm2', system_info=SYSTEM_INFO)
        resolution = parser.AskResolution(
            rule, request, user=None,
            targets_for_ask=['test-vm2', 'test-vm3'],
            default_target=None)
        with self.assertRaises(exc.AccessDenied) as e:
            resolution.handle_user_response(True, 'test-no-dvm')
        self.assertTrue(e.exception.notify)

    def test_113_handle_user_response_deny_normal(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask',
            filepath='filename', lineno=12)
        request = _req('test-vm1', 'test-vm2')
        resolution = parser.AskResolution(
            rule, request, user=None,
            targets_for_ask=['test-vm1', 'test-vm2'],
            default_target=None)
        with self.assertRaises(exc.AccessDenied) as e:
            resolution.handle_user_response(False, '')
        self.assertFalse(e.exception.notify)

    def test_114_handle_user_response_deny_normal_notify(self):
        rule = parser.Rule.from_line(None, '* * @anyvm @anyvm ask notify=yes',
            filepath='filename', lineno=12)
        request = _req('test-vm1', 'test-vm2')
        resolution = parser.AskResolution(
            rule, request, user=None,
            targets_for_ask=['test-vm1', 'test-vm2'],
            default_target=None)
        with self.assertRaises(exc.AccessDenied) as e:
            resolution.handle_user_response(False, '')
        self.assertTrue(e.exception.notify)

    def test_115_handle_user_response_with_default_target(self):
        rule = parser.Rule.from_line(None,
            '* * @anyvm @anyvm ask default_target=test-vm2',
            filepath='filename', lineno=12)
        request = _req('test-vm1', 'test-vm2')
        resolution = parser.AskResolution(
            rule, request, user=None,
            targets_for_ask=['test-vm2', 'test-vm3'],
            default_target='test-vm2')
        resolution = resolution.handle_user_response(True, 'test-vm2')
        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.target, 'test-vm2')

    @unittest.mock.patch('qrexec.utils.qubesd_call')
    def test_120_execute(self, mock_qubesd_call):
        with unittest.mock.patch('asyncio.create_subprocess_exec', new=AsyncMock()) as mock_subprocess:
            asyncio.run(self._test_120_execute(mock_subprocess, mock_qubesd_call))

    async def _test_120_execute(self, mock_subprocess, mock_qubesd_call):
        rule = parser.Rule.from_line(None,
            '* * @anyvm @anyvm allow',
            filepath='filename', lineno=12)
        request = _req('test-vm1', 'test-vm2')
        resolution = parser.AllowResolution(
            rule, request, user=None, target='test-vm2')
        mock_subprocess.return_value.returncode = 0
        await resolution.execute('some-ident')
        self.assertEqual(mock_qubesd_call.mock_calls,
            [unittest.mock.call('test-vm2', 'admin.vm.Start')])
        self.assertEqual(mock_subprocess.mock_calls,
            [unittest.mock.call(QREXEC_CLIENT, '-d', 'test-vm2',
             '-c', 'some-ident', '-E',
             'DEFAULT:QUBESRPC test.Service+argument test-vm1'),
             unittest.mock.call().communicate()])

    @unittest.expectedFailure
    @unittest.mock.patch('qrexec.utils.qubesd_call')
    def test_121_execute_dom0(self, mock_qubesd_call):
        with unittest.mock.patch('asyncio.create_subprocess_exec', new=AsyncMock()) as mock_subprocess:
            asyncio.run(self._test_121_execute_dom0(mock_subprocess, mock_qubesd_call))

    async def _test_121_execute_dom0(self, mock_subprocess, mock_qubesd_call):
        rule = parser.Rule.from_line(None,
            '* * @anyvm dom0 allow',
            filepath='filename', lineno=12)
        request = _req('test-vm1', 'dom0')
        resolution = parser.AllowResolution(
            rule, request, user=None, target='dom0')
        mock_subprocess.return_value.returncode = 0
        await resolution.execute('some-ident')
        self.assertEqual(mock_qubesd_call.mock_calls, [])
        self.assertEqual(mock_subprocess.mock_calls,
            [unittest.mock.call([QREXEC_CLIENT, '-d', 'dom0',
             '-c', 'some-ident', '-E',
             'QUBESRPC test.Service+argument test-vm1 name dom0'])])

    @unittest.mock.patch('qrexec.utils.qubesd_call')
    def test_121_execute_dom0_keyword(self, mock_qubesd_call):
        with unittest.mock.patch('asyncio.create_subprocess_exec', new=AsyncMock()) as mock_subprocess:
            asyncio.run(self._test_121_execute_dom0_keyword(mock_subprocess, mock_qubesd_call))

    async def _test_121_execute_dom0_keyword(self, mock_subprocess, mock_qubesd_call):
        rule = parser.Rule.from_line(None,
            '* * @anyvm dom0 allow',
            filepath='filename', lineno=12)
        request = _req('test-vm1', '@adminvm')
        resolution = parser.AllowResolution(
            rule, request, user=None, target='@adminvm')
        mock_subprocess.return_value.returncode = 0
        await resolution.execute('some-ident')
        self.assertEqual(mock_qubesd_call.mock_calls, [])
        self.assertEqual(mock_subprocess.mock_calls,
            [unittest.mock.call(QREXEC_CLIENT, '-d', '@adminvm',
             '-c', 'some-ident', '-E',
             'QUBESRPC test.Service+argument test-vm1 keyword adminvm'),
             unittest.mock.call().communicate()])

    @unittest.mock.patch('qrexec.utils.qubesd_call')
    def test_122_execute_dispvm(self, mock_qubesd_call):
        with unittest.mock.patch('asyncio.create_subprocess_exec', new=AsyncMock()) as mock_subprocess:
            asyncio.run(self._test_122_execute_dispvm(mock_subprocess, mock_qubesd_call))

    async def _test_122_execute_dispvm(self, mock_subprocess, mock_qubesd_call):
        rule = parser.Rule.from_line(None,
            '* * @anyvm @dispvm:default-dvm allow',
            filepath='filename', lineno=12)
        request = _req('test-vm1', '@dispvm:default-dvm')
        resolution = parser.AllowResolution(
            rule, request, user=None,
            target=parser.DispVMTemplate('@dispvm:default-dvm'))
        mock_qubesd_call.side_effect = (lambda target, call:
            b'dispvm-name' if call == 'admin.vm.CreateDisposable' else
            unittest.mock.DEFAULT)
        mock_subprocess.return_value.returncode = 0
        await resolution.execute('some-ident')
        self.assertEqual(mock_qubesd_call.mock_calls,
            [unittest.mock.call('default-dvm', 'admin.vm.CreateDisposable'),
             unittest.mock.call('dispvm-name', 'admin.vm.Start'),
             unittest.mock.call('dispvm-name', 'admin.vm.Kill')])
        self.assertEqual(mock_subprocess.mock_calls,
            [unittest.mock.call(QREXEC_CLIENT, '-d', 'dispvm-name',
             '-c', 'some-ident', '-E', '-W',
             'DEFAULT:QUBESRPC test.Service+argument test-vm1'),
             unittest.mock.call().communicate()])

    @unittest.mock.patch('qrexec.utils.qubesd_call')
    def test_123_execute_already_running(self, mock_qubesd_call):
        with unittest.mock.patch('asyncio.create_subprocess_exec', new=AsyncMock()) as mock_subprocess:
            asyncio.run(self._test_123_execute_already_running(mock_subprocess, mock_qubesd_call))

    async def _test_123_execute_already_running(self, mock_subprocess,
            mock_qubesd_call):
        rule = parser.Rule.from_line(None,
            '* * @anyvm @anyvm allow',
            filepath='filename', lineno=12)
        request = _req('test-vm1', 'test-vm2')
        resolution = parser.AllowResolution(
            rule, request, user=None, target='test-vm2')
        mock_qubesd_call.side_effect = \
            exc.QubesMgmtException('QubesVMNotHaltedError')
        mock_subprocess.return_value.returncode = 0
        await resolution.execute('some-ident')
        self.assertEqual(mock_qubesd_call.mock_calls,
            [unittest.mock.call('test-vm2', 'admin.vm.Start')])
        self.assertEqual(mock_subprocess.mock_calls,
            [unittest.mock.call(QREXEC_CLIENT, '-d', 'test-vm2',
             '-c', 'some-ident', '-E',
             'DEFAULT:QUBESRPC test.Service+argument test-vm1'),
             unittest.mock.call().communicate()])

    @unittest.mock.patch('qrexec.utils.qubesd_call')
    def test_124_execute_startup_error(self, mock_qubesd_call):
        with unittest.mock.patch('asyncio.create_subprocess_exec', new=AsyncMock()) as mock_subprocess:
            asyncio.run(self._test_124_execute_startup_error(mock_subprocess, mock_qubesd_call))

    async def _test_124_execute_startup_error(self, mock_subprocess,
            mock_qubesd_call):
        rule = parser.Rule.from_line(None,
            '* * @anyvm @anyvm allow',
            filepath='filename', lineno=12)
        request = parser.Request('test.service', '+', 'test-vm1',
            'test-vm2', system_info=SYSTEM_INFO)
        resolution = parser.AllowResolution(
            rule, request, user=None, target='test-vm2')
        mock_qubesd_call.side_effect = \
            exc.QubesMgmtException('QubesVMError')
        with self.assertRaises(exc.QubesMgmtException):
            await resolution.execute('some-ident')
        self.assertEqual(mock_qubesd_call.mock_calls,
            [unittest.mock.call('test-vm2', 'admin.vm.Start')])
        self.assertEqual(mock_subprocess.mock_calls, [])

    @unittest.mock.patch('qrexec.utils.qubesd_call')
    def test_125_execute_call_error(self, mock_qubesd_call):
        with unittest.mock.patch('asyncio.create_subprocess_exec', new=AsyncMock()) as mock_subprocess:
            asyncio.run(self._test_125_execute_call_error(mock_subprocess, mock_qubesd_call))

    async def _test_125_execute_call_error(self, mock_subprocess,
            __mock_qubesd_call):
        rule = parser.Rule.from_line(None,
            '* * @anyvm @anyvm allow',
            filepath='filename', lineno=12)
        request = parser.Request('test.service', '+', 'test-vm1',
            'test-vm2', system_info=SYSTEM_INFO)
        resolution = parser.AllowResolution(
            rule, request, user=None, target='test-vm2')
        mock_subprocess.return_value.returncode = 1
        with self.assertRaises(exc.ExecutionFailed):
            await resolution.execute('some-ident')


#class TC_30_Misc(qubes.tests.QubesTestCase):
class TC_50_Misc(unittest.TestCase):
    @unittest.mock.patch('socket.socket')
    def test_000_qubesd_call(self, mock_socket):
        mock_config = {
            'return_value.makefile.return_value.read.return_value': b'0\x00data'
        }
        mock_socket.configure_mock(**mock_config)
        result = utils.qubesd_call('test', 'internal.method')
        self.assertEqual(result, b'data')
        self.assertEqual(mock_socket.mock_calls, [
            unittest.mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
            unittest.mock.call().connect(QUBESD_INTERNAL_SOCK),
            unittest.mock.call().sendall(b'internal.method+ dom0 name test\0'),
            unittest.mock.call().shutdown(socket.SHUT_WR),
            unittest.mock.call().makefile('rb'),
            unittest.mock.call().makefile().read(),
        ])

    @unittest.mock.patch('socket.socket')
    def test_001_qubesd_call_arg_payload(self, mock_socket):
        mock_config = {
            'return_value.makefile.return_value.read.return_value': b'0\x00data'
        }
        mock_socket.configure_mock(**mock_config)
        result = utils.qubesd_call('test', 'internal.method', 'arg',
            b'payload')
        self.assertEqual(result, b'data')
        self.assertEqual(mock_socket.mock_calls, [
            unittest.mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
            unittest.mock.call().connect(QUBESD_INTERNAL_SOCK),
            unittest.mock.call().sendall(b'internal.method+arg dom0 name test\0'),
            unittest.mock.call().sendall(b'payload'),
            unittest.mock.call().shutdown(socket.SHUT_WR),
            unittest.mock.call().makefile('rb'),
            unittest.mock.call().makefile().read(),
        ])

    @unittest.mock.patch('socket.socket')
    def test_002_qubesd_call_exception(self, mock_socket):
        mock_config = {
            'return_value.makefile.return_value.read.return_value':
                b'2\x00SomeError\x00traceback\x00message\x00'
        }
        mock_socket.configure_mock(**mock_config)
        with self.assertRaises(exc.QubesMgmtException) as err:
            utils.qubesd_call('test', 'internal.method')
        self.assertEqual(err.exception.exc_type, 'SomeError')
        self.assertEqual(mock_socket.mock_calls, [
            unittest.mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
            unittest.mock.call().connect(QUBESD_INTERNAL_SOCK),
            unittest.mock.call().sendall(b'internal.method+ dom0 name test\0'),
            unittest.mock.call().shutdown(socket.SHUT_WR),
            unittest.mock.call().makefile('rb'),
            unittest.mock.call().makefile().read(),
        ])

class TC_90_Compat40(unittest.TestCase):
    def test_001_loader(self):
        policy = parser.TestPolicy(policy={'__main__': '!compat-4.0'},
            policy_compat={'test.Allow': '$anyvm $anyvm allow'})
        policy.evaluate(parser.Request(
            'test.Allow', '+', 'test-vm1', 'test-vm2',
            system_info=SYSTEM_INFO))

    def test_100_implicit_deny(self):
        policy = parser.TestPolicy(
            policy={'__main__': '''
                test.AllowBefore    * @anyvm @anyvm allow
                !compat-4.0
                test.AllowAfter     * @anyvm @anyvm allow
                test.ImplicitDeny   * @anyvm @anyvm allow
            '''},
            policy_compat={
                'test.AllowAfter': '''
                    test-vm1 test-vm2 allow
                ''',
                'test.ImplicitDeny+arg': '''
                    test-vm1 test-vm2 allow
                ''',
            })

        policy.evaluate(parser.Request(
            'test.AllowAfter', '+', 'test-vm1', 'test-vm2',
            system_info=SYSTEM_INFO))
        policy.evaluate(parser.Request(
            'test.AllowAfter', '+', 'test-vm1', 'test-vm3',
            system_info=SYSTEM_INFO))

        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(parser.Request(
                'test.ImplicitDeny', '+arg', 'test-vm1', 'test-vm3',
                system_info=SYSTEM_INFO))
