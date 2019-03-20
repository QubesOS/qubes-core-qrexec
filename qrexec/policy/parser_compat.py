# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2019  Wojtek Porczyk <woju@invisiblethingslab.com>
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

import collections
import functools
import logging
import pathlib

from .. import POLICYPATH_OLD
from ..exc import PolicySyntaxError
from . import parser

@functools.total_ordering
class _NoArgumentLastKey:
    def __init__(self, arg):
        self.arg = arg
    def __eq__(self, other):
        return self.arg == other.arg
    def __lt__(self, other):
        return self.arg == '*' or self.arg < other.arg

def walk_compat_files(legacy_path=POLICYPATH_OLD):
    '''Walks files in correct order for generating compat policy.

    Yields:
        (service, argument, filepath)
    '''

    services = collections.defaultdict(dict)

    for filepath in legacy_path.iterdir():
        if not filepath.is_file():
            logging.info('ignoring %s (not a file)', filepath)
            continue

        invalid_chars = parser.get_invalid_characters(filepath.name)
        if invalid_chars:
            logging.info('ignoring %s (invalid characters: %r)',
                filepath, invalid_chars)
            continue

        service, argument = parser.parse_service_and_argument(filepath.name,
            no_arg='*')
        services[service][argument] = filepath

    for service in sorted(services):
        for argument in sorted(services[service], key=_NoArgumentLastKey):
            yield service, argument, services[service][argument]

class Compat40Parser(parser.AbstractDirectoryLoader, parser.AbstractFileLoader):
    def __init__(self, *, master, legacy_path=POLICYPATH_OLD):
        self.legacy_path = pathlib.Path(legacy_path)
        self.master = master

    def execute(self, *, filepath, lineno):
        for service, argument, path in walk_compat_files(self.legacy_path):
            self.handle_include_service(service, argument, path,
                filepath=filepath, lineno=lineno)

            # After each file describing particular argument we add deny lines,
            # which were implicit. After non-specific we don't do that so the
            # default policy will not be shadowed.
            if argument != '*':
                self.handle_rule(self.rule_type.from_line_service(self,
                    service, argument, '@anyvm @anyvm deny',
                    filepath=path, lineno=None))
                self.handle_rule(self.rule_type.from_line_service(self,
                    service, argument, '@anyvm @adminvm deny',
                    filepath=path, lineno=None))

    def resolve_path(self, included_path):
        return (self.legacy_path / included_path).resolve()

    def handle_rule(self, rule, *, filepath, lineno):
        return self.master.handle_rule(rule, filepath=filepath, lineno=lineno)

    def load_policy_file(self, file, filepath):
        raise RuntimeError('this method should not be called')

    def handle_compat40(self, *, filepath, lineno):
        raise PolicySyntaxError(filepath, lineno,
            '!compat-4.0 is not recursive')
