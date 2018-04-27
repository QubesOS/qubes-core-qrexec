# coding=utf-8
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2013-2015  Joanna Rutkowska <joanna@invisiblethingslab.com>
# Copyright (C) 2013-2017  Marek Marczykowski-Górecki
#                                   <marmarek@invisiblethingslab.com>
# Copyright (C) 2018  Wojtek Porczyk <woju@invisiblethingslab.com>
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

''' Qrexec policy parser and evaluator '''

import abc
import enum
import logging
import pathlib
import subprocess

from .. import QREXEC_CLIENT, POLICYPATH
from ..exc import (
    AccessDenied, PolicySyntaxError, PolicyNotFound, QubesMgmtException)
from ..utils import qubesd_call


class Action(enum.Enum):
    ''' Action as defined by policy '''
    allow = 1
    deny = 2
    ask = 3

def is_special_value(value):
    '''Check if given source/target specification is special (keyword) value
    '''
    return value.startswith('@')

def verify_target_value(system_info, value):
    ''' Check if given value names valid target

    This function check if given value is not only syntactically correct,
    but also if names valid service call target (existing domain,
    or valid @dispvm like keyword)

    :param system_info: information about the system
    :param value: value to be checked
    '''
    if value == '@dispvm':
        return True
    elif value == '@adminvm':
        return True
    elif value.startswith('@dispvm:'):
        dispvm_base = value.split(':', 1)[1]
        if dispvm_base not in system_info['domains']:
            return False
        dispvm_base_info = system_info['domains'][dispvm_base]
        return bool(dispvm_base_info['template_for_dispvms'])
    else:
        return value in system_info['domains']


def verify_special_value(value, for_target=True, specific_target=False):
    '''
    Verify if given special VM-specifier ('@...') is valid

    :param value: value to verify
    :param for_target: should classify target-only values as valid (
        '@default', '@dispvm')
    :param specific_target: allow only values naming specific target
        (for use with target=, default= etc)
    :return: True or False
    '''
    # pylint: disable=too-many-return-statements

    # values used only for matching VMs, not naming specific one (for actual
    # call target)
    if not specific_target:
        if value.startswith('@tag:') and len(value) > len('@tag:'):
            return True
        if value.startswith('@type:') and len(value) > len('@type:'):
            return True
        if for_target and value.startswith('@dispvm:@tag:') and \
                len(value) > len('@dispvm:@tag:'):
            return True
        if value == '@anyvm':
            return True
        if for_target and value == '@default':
            return True

    # those can be used to name one specific call VM
    if value == '@adminvm':
        return True
    # allow only specific dispvm, not based on any @xxx keyword - don't name
    # @tag here specifically, to work also with any future keywords
    if for_target and value.startswith('@dispvm:') and \
            not value.startswith('@dispvm:@'):
        return True
    if for_target and value == '@dispvm':
        return True
    return False


class PolicyRule(object):
    ''' A single line of policy file '''
    # pylint: disable=too-many-instance-attributes
    def __init__(self, line, filename=None, lineno=None):
        '''
        Load a single line of qrexec policy and check its syntax.
        Do not verify existence of named objects.

        :raise PolicySyntaxError: when syntax error is found

        :param line: a single line of actual qrexec policy (not a comment,
        empty line or @include)
        :param filename: name of the file from which this line is loaded
        :param lineno: line number from which this line is loaded
        '''
        # pylint: disable=too-many-branches

        self.lineno = lineno
        self.filename = filename

        try:
            self.source, self.target, self.full_action = line.split(maxsplit=2)
        except ValueError:
            raise PolicySyntaxError(filename, lineno, 'wrong number of fields')

        (action, *params) = self.full_action.replace(',', ' ').split()
        try:
            self.action = Action[action]
        except KeyError:
            raise PolicySyntaxError(filename, lineno,
                'invalid action: {}'.format(action))

        #: alternative target, used instead of the one specified by the caller
        self.override_target = None

        #: alternative user, used instead of vm.default_user
        self.override_user = None

        #: default target when asking the user for confirmation
        self.default_target = None

        for param in params:
            try:
                param_name, value = param.split('=')
            except ValueError:
                raise PolicySyntaxError(filename, lineno,
                    'invalid action parameter syntax: {}'.format(param))
            if param_name == 'target':
                if self.action == Action.deny:
                    raise PolicySyntaxError(filename, lineno,
                        'target= option not allowed for deny action')
                self.override_target = value
            elif param_name == 'user':
                if self.action == Action.deny:
                    raise PolicySyntaxError(filename, lineno,
                        'user= option not allowed for deny action')
                self.override_user = value
            elif param_name == 'default_target':
                if self.action != Action.ask:
                    raise PolicySyntaxError(filename, lineno,
                        'default_target= option allowed only for ask action')
                self.default_target = value
            else:
                raise PolicySyntaxError(filename, lineno,
                    'invalid option {} for {} action'.format(param, action))

        # verify special values
        if is_special_value(self.source):
            if not verify_special_value(self.source, False, False):
                raise PolicySyntaxError(filename, lineno,
                    'invalid source specification: {}'.format(self.source))

        if is_special_value(self.target):
            if not verify_special_value(self.target, True, False):
                raise PolicySyntaxError(filename, lineno,
                    'invalid target specification: {}'.format(self.target))

        if self.target == '@default' \
                and self.action == Action.allow \
                and self.override_target is None:
            raise PolicySyntaxError(filename, lineno,
                'allow action for @default rule must specify target= option')

        if self.override_target is not None:
            if is_special_value(self.override_target) and \
                    not verify_special_value(self.override_target, True, True):
                raise PolicySyntaxError(filename, lineno,
                    'target= option needs to name specific target')

        if self.default_target is not None:
            if is_special_value(self.default_target) and \
                    not verify_special_value(self.default_target, True, True):
                raise PolicySyntaxError(filename, lineno,
                    'target= option needs to name specific target')

    @staticmethod
    def is_match_single(system_info, policy_value, value):
        '''
        Evaluate if a single value (VM name or '@default') matches policy
        specification

        :param system_info: information about the system
        :param policy_value: value from qrexec policy (either self.source or
            self.target)
        :param value: value to be compared (source or target)
        :return: True or False
        '''
        # pylint: disable=too-many-return-statements

        # not specified target matches only with @default and @anyvm policy
        # entry
        if value == '@default':
            return policy_value in ('@default', '@anyvm')

        # if specific target used, check if it's valid
        # this function (is_match_single) is also used for checking call source
        # values, but this isn't a problem, because it will always be a
        # domain name (not @dispvm or such) - this is guaranteed by a nature
        # of qrexec call
        if not verify_target_value(system_info, value):
            return False

        # handle @adminvm keyword
        if policy_value == 'dom0':
            # TODO: log a warning in Qubes 4.1
            policy_value = '@adminvm'

        if value == 'dom0':
            value = '@adminvm'

        # allow any _valid_, non-dom0 target
        if policy_value == '@anyvm':
            return value != '@adminvm'

        # exact match, including @dispvm* and @adminvm
        if value == policy_value:
            return True

        # DispVM request, using tags to match
        if policy_value.startswith('@dispvm:@tag:') \
                and value.startswith('@dispvm:'):
            tag = policy_value.split(':', 2)[2]
            dispvm_base = value.split(':', 1)[1]
            # already checked for existence by verify_target_value call
            dispvm_base_info = system_info['domains'][dispvm_base]
            return tag in dispvm_base_info['tags']

        # if @dispvm* not matched above, reject it; default DispVM (bare
        # @dispvm) was resolved by the caller
        if value.startswith('@dispvm:'):
            return False

        # require @adminvm to be matched explicitly (not through @tag or @type)
        # - if not matched already, reject it
        if value == '@adminvm':
            return False

        # at this point, value name a specific target
        domain_info = system_info['domains'][value]

        if policy_value.startswith('@tag:'):
            tag = policy_value.split(':', 1)[1]
            return tag in domain_info['tags']

        if policy_value.startswith('@type:'):
            type_ = policy_value.split(':', 1)[1]
            return type_ == domain_info['type']

        return False

    def is_match(self, system_info, source, target):
        '''
        Check if given (source, target) matches this policy line.

        :param system_info: information about the system - available VMs,
            their types, labels, tags etc. as returned by
            :py:func:`app_to_system_info`
        :param source: name of the source VM
        :param target: name of the target VM, or None if not specified
        :return: True or False
        '''

        if not self.is_match_single(system_info, self.source, source):
            return False
        # @dispvm in policy matches _only_ @dispvm (but not @dispvm:some-vm,
        # even if that would be the default one)
        if self.target == '@dispvm' and target == '@dispvm':
            return True
        if target == '@dispvm':
            # resolve default DispVM, to check all kinds of @dispvm:*
            default_dispvm = system_info['domains'][source]['default_dispvm']
            if default_dispvm is None:
                # if this VM have no default DispVM, match only with @anyvm
                return self.target == '@anyvm'
            target = '@dispvm:' + default_dispvm
        if not self.is_match_single(system_info, self.target, target):
            return False
        return True

    def expand_target(self, system_info):
        '''
        Return domains matching target of this policy line

        :param system_info: information about the system
        :return: matching domains
        '''
        # pylint: disable=too-many-branches

        if self.target.startswith('@tag:'):
            tag = self.target.split(':', 1)[1]
            for name, domain in system_info['domains'].items():
                if tag in domain['tags']:
                    yield name
        elif self.target.startswith('@type:'):
            type_ = self.target.split(':', 1)[1]
            for name, domain in system_info['domains'].items():
                if type_ == domain['type']:
                    yield name
        elif self.target == '@anyvm':
            for name, domain in system_info['domains'].items():
                if name != 'dom0':
                    yield name
                if domain['template_for_dispvms']:
                    yield '@dispvm:' + name
            yield '@dispvm'
        elif self.target.startswith('@dispvm:@tag:'):
            tag = self.target.split(':', 2)[2]
            for name, domain in system_info['domains'].items():
                if tag in domain['tags']:
                    if domain['template_for_dispvms']:
                        yield '@dispvm:' + name
        elif self.target.startswith('@dispvm:'):
            dispvm_base = self.target.split(':', 1)[1]
            try:
                if system_info['domains'][dispvm_base]['template_for_dispvms']:
                    yield self.target
            except KeyError:
                # TODO log a warning?
                pass
        elif self.target == '@adminvm':
            yield self.target
        elif self.target == '@dispvm':
            yield self.target
        else:
            if self.target in system_info['domains']:
                yield self.target

    def expand_override_target(self, system_info, source):
        '''
        Replace '@dispvm' with specific '@dispvm:...' value, based on qrexec
        call source.

        :param system_info: System information
        :param source: Source domain name
        :return: :py:attr:`override_target` with '@dispvm' substituted
        '''
        if self.override_target == '@dispvm':
            if system_info['domains'][source]['default_dispvm'] is None:
                return None
            return '@dispvm:' + system_info['domains'][source]['default_dispvm']
        else:
            return self.override_target


class PolicyAction(object):
    ''' Object representing positive policy evaluation result -
    either ask or allow action '''
    def __init__(self, service, source, target, rule, original_target,
            targets_for_ask=None):
        # pylint: disable=too-many-arguments

        #: service name
        self.service = service
        #: calling domain
        self.source = source
        #: target domain the service should be connected to, None if
        # not chosen yet
        if targets_for_ask is None or target in targets_for_ask:
            self.target = target
        else:
            # TODO: log a warning?
            self.target = None
        #: original target specified by the caller
        self.original_target = original_target
        #: targets for the user to choose from
        self.targets_for_ask = targets_for_ask
        #: policy rule from which this action is derived
        self.rule = rule
        if rule.action == Action.deny:
            # this should be really rejected by Policy.eval()
            raise AccessDenied(
                'denied by policy {}:{}'.format(rule.filename, rule.lineno))
        elif rule.action == Action.ask:
            assert targets_for_ask is not None
        elif rule.action == Action.allow:
            assert targets_for_ask is None
            assert target is not None
        self.action = rule.action

    def handle_user_response(self, response, target=None):
        '''
        Handle user response for the 'ask' action

        :param response: whether the call was allowed or denied (bool)
        :param target: target chosen by the user (if reponse==True)
        :return: None
        '''
        # pylint: disable=redefined-variable-type
        assert self.action == Action.ask
        if response:
            assert target in self.targets_for_ask
            self.target = target
            self.action = Action.allow
        else:
            self.action = Action.deny
            raise AccessDenied(
                'denied by the user {}:{}'.format(self.rule.filename,
                    self.rule.lineno))

    def execute(self, caller_ident):
        ''' Execute allowed service call

        :param caller_ident: Service caller ident
            (`process_ident,source_name, source_id`)
        '''
        assert self.action == Action.allow
        assert self.target is not None

        if self.target == '@adminvm':
            self.target = 'dom0'
        if self.target == 'dom0':
            original_target_type = \
                'keyword' if is_special_value(self.original_target) else 'name'
            original_target = self.original_target.lstrip('@')
            cmd = \
                'QUBESRPC {service} {source} {original_target_type} ' \
                '{original_target}'.format(
                    service=self.service,
                    source=self.source,
                    original_target_type=original_target_type,
                    original_target=original_target)
        else:
            cmd = '{user}:QUBESRPC {service} {source}'.format(
                user=(self.rule.override_user or 'DEFAULT'),
                service=self.service,
                source=self.source)
        if self.target.startswith('@dispvm:'):
            target = self.spawn_dispvm()
            dispvm = True
        else:
            target = self.target
            dispvm = False
            self.ensure_target_running()
        qrexec_opts = ['-d', target, '-c', caller_ident]
        if dispvm:
            qrexec_opts.append('-W')
        try:
            subprocess.call([QREXEC_CLIENT] + qrexec_opts + [cmd])
        finally:
            if dispvm:
                self.cleanup_dispvm(target)


    def spawn_dispvm(self):
        '''
        Create and start Disposable VM based on AppVM specified in
        :py:attr:`target`
        :return: name of new Disposable VM
        '''
        base_appvm = self.target.split(':', 1)[1]
        dispvm_name = qubesd_call(base_appvm, 'admin.vm.CreateDisposable')
        dispvm_name = dispvm_name.decode('ascii')
        qubesd_call(dispvm_name, 'admin.vm.Start')
        return dispvm_name

    def ensure_target_running(self):
        '''
        Start domain if not running already

        :return: None
        '''
        if self.target == 'dom0':
            return
        try:
            qubesd_call(self.target, 'admin.vm.Start')
        except QubesMgmtException as err:
            if err.exc_type == 'QubesVMNotHaltedError':
                pass
            else:
                raise

    @staticmethod
    def cleanup_dispvm(dispvm):
        '''
        Kill and remove Disposable VM

        :param dispvm: name of Disposable VM
        :return: None
        '''
        qubesd_call(dispvm, 'admin.vm.Kill')


class AbstractPolicyParser(metaclass=abc.ABCMeta):
    '''A minimal, pluggable, validating policy parser'''
    policy_path = POLICYPATH

    def __init__(self, *, policy_path=None):
        if policy_path is not None:
            self.policy_path = pathlib.Path(policy_path)

    def load_policy_file(self, file, filename=None):
        '''Parse a policy file'''
        if filename is None:
            if isinstance(file, (str, pathlib.Path)):
                filename = str(file)
                file = open(filename)
            else:
                try:
                    filename = file.name
                except AttributeError:
                    filename = '<unknown>'

        for lineno, line in enumerate(file, start=1):
            line = line.strip()

            # skip empty lines and comments
            if not line or line[0] == '#':
                continue

            # compatibility with old keywords notation
            line = line.replace('$', '@')

            if line.startswith('@include:'):
                self.handle_include(line.split(':', 1)[-1],
                    filename=filename, lineno=lineno)
                continue

            # this can raise PolicySyntaxError on its own
            self.handle_rule(PolicyRule(line, filename, lineno),
                filename=filename, lineno=lineno)

        return self

    @abc.abstractmethod
    def handle_include(self, included_path, filename, lineno):
        '''Handle ``@include:`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_rule(self, rule, filename, lineno):
        '''Handle a line with a rule.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()


class Policy(AbstractPolicyParser):
    ''' Full policy for a given service

    Usage:
    >>> system_info = get_system_info()
    >>> policy = Policy('some-service')
    >>> action = policy.evaluate(system_info, 'source-name', 'target-name')
    >>> if action.action == Action.ask:
    >>>     # ... ask the user, see action.targets_for_ask ...
    >>>     action.handle_user_response(response, target_chosen_by_user)
    >>> action.execute('process-ident')

    '''

    def __init__(self, service, policy_path=None):
        super().__init__(policy_path=policy_path)

        policy_file = self.policy_path / service
        if not policy_file.exists():
            # fallback to policy without specific argument set (if any)
            policy_file = self.policy_path / service.split('+')[0]
        if not policy_file.exists():
            raise PolicyNotFound(service)

        #: service name
        self.service = service

        #: list of PolicyLine objects
        self.policy_rules = []
        try:
            self.load_policy_file(policy_file)
        except OSError as err:
            raise AccessDenied(
                'failed to load {} file: {!s}'.format(err.filename, err))


    def handle_include(self, included_path, filename, lineno):
        # pylint: disable=unused-argument
        included_path = self.policy_path / included_path
        self.load_policy_file(included_path)

    def handle_rule(self, rule, filename, lineno):
        # pylint: disable=unused-argument
        self.policy_rules.append(rule)


    def find_matching_rule(self, system_info, source, target):
        ''' Find the first rule matching given arguments '''

        for rule in self.policy_rules:
            if rule.is_match(system_info, source, target):
                return rule
        raise AccessDenied('no matching rule found')


    def collect_targets_for_ask(self, system_info, source):
        ''' Collect targets the user can choose from in 'ask' action

        Word 'targets' is used intentionally instead of 'domains', because it
        can also contains @dispvm like keywords.
        '''
        targets = set()

        # iterate over rules in reversed order to easier handle 'deny'
        # actions - simply remove matching domains from allowed set
        for rule in reversed(self.policy_rules):
            if rule.is_match_single(system_info, rule.source, source):
                if rule.action == Action.deny:
                    targets -= set(rule.expand_target(system_info))
                else:
                    if rule.override_target is not None:
                        override_target = rule.expand_override_target(
                            system_info, source)
                        if verify_target_value(system_info, override_target):
                            targets.add(rule.override_target)
                    else:
                        targets.update(rule.expand_target(system_info))

        # expand default DispVM
        if '@dispvm' in targets:
            targets.remove('@dispvm')
            if system_info['domains'][source]['default_dispvm'] is not None:
                dispvm = '@dispvm:' + \
                    system_info['domains'][source]['default_dispvm']
                if verify_target_value(system_info, dispvm):
                    targets.add(dispvm)

        # expand other keywords
        if '@adminvm' in targets:
            targets.remove('@adminvm')
            targets.add('dom0')

        return targets

    def evaluate(self, system_info, source, target):
        ''' Evaluate policy

        :raise AccessDenied: when action should be denied unconditionally

        :return tuple(rule, considered_targets) - where considered targets is a
        list of possible targets for 'ask' action (rule.action == Action.ask)
        '''
        # pylint: disable=too-many-branches
        if target == '':
            target = '@default'
        rule = self.find_matching_rule(system_info, source, target)
        if rule.action == Action.deny:
            raise AccessDenied(
                'denied by policy {}:{}'.format(rule.filename, rule.lineno))

        if rule.override_target is not None:
            override_target = rule.expand_override_target(system_info, source)
            if not verify_target_value(system_info, override_target):
                raise AccessDenied('invalid target= value in {}:{}'.format(
                    rule.filename, rule.lineno))
            actual_target = override_target
        else:
            actual_target = target

        if rule.action == Action.ask:
            if rule.override_target is not None:
                targets = [actual_target]
            else:
                targets = list(
                    self.collect_targets_for_ask(system_info, source))
            if not targets:
                raise AccessDenied(
                    'policy define \'ask\' action at {}:{} but no target is '
                    'available to choose from'.format(
                        rule.filename, rule.lineno))
            return PolicyAction(self.service, source, rule.default_target,
                rule, target, targets)
        elif rule.action == Action.allow:
            if actual_target == '@default':
                raise AccessDenied(
                    'policy define \'allow\' action at {}:{} but no target is '
                    'specified by caller or policy'.format(
                        rule.filename, rule.lineno))
            if actual_target == '@dispvm':
                if system_info['domains'][source]['default_dispvm'] is None:
                    raise AccessDenied(
                        'policy define \'allow\' action to @dispvm at {}:{} '
                        'but no DispVM base is set for this VM'.format(
                            rule.filename, rule.lineno))
                actual_target = '@dispvm:' + \
                    system_info['domains'][source]['default_dispvm']

            return PolicyAction(self.service, source,
                actual_target, rule, target)
        else:
            # should be unreachable
            raise AccessDenied(
                'invalid action?! {}:{}'.format(rule.filename, rule.lineno))

class ValidateIncludesParser(AbstractPolicyParser):
    '''A parser that checks if included file does indeed exist.

    The included file is not read, because if it exists, it is assumed it
    already passed syntax check.
    '''
    def handle_include(self, included_path, filename, lineno):
        # TODO disallow anything other that @include:[include/]<file>
        if not (self.policy_path / included_path).is_file():
            raise PolicySyntaxError(filename, lineno,
                'included path {!s} does not exist'.format(included_path))

    def handle_rule(self, rule, filename, lineno):
        pass

class CheckIfNotIncludedParser(AbstractPolicyParser):
    '''A parser that checks if a particular file is *not* included.

    This is used while removing a particular file, to check that it is not used
    anywhere else.
    '''
    def __init__(self, *args, to_be_removed, **kwds):
        self.to_be_removed = self.policy_path / to_be_removed
        super().__init__(*args, **kwds)

    def handle_include(self, included_path, filename, lineno):
        included_path = self.policy_path / included_path
        if included_path.samefile(self.to_be_removed):
            raise PolicySyntaxError(filename, lineno,
                'included path {!s}'.format(included_path))

    def handle_rule(self, rule, filename, lineno):
        pass

class ToposortParser(AbstractPolicyParser):
    '''A helper for topological sorting the policy files'''

    def __init__(self, *args, filepath, **kwds):
        super().__init__(*args, **kwds)
        self.filepath = filepath
        self.file = open(str(self.policy_path / filepath))
        self.included_paths = set()
        self.state = None
        self.load_policy_file(self.file, filename=str(self.filepath))
        self.file.seek(0)

    def handle_include(self, included_path, filename, lineno):
        logging.debug('ToposortParser(filepath=%r).handle_include(included_path=%r)',
            self.filepath, included_path)
        if '/' in included_path and (
                not included_path.startswith('include/')
                or included_path.count('/') > 1):
            # TODO make this an error, since we shouldn't accept this anyway
            logging.warning('ignoring path %r included in %s on line %d; '
                'expect problems with import order',
                included_path, filename, lineno)
            return
        self.included_paths.add(included_path)

    def handle_rule(self, rule, filename, lineno):
        pass


# TODO this should inherit from common policy exception
class PolicyDirectoryLoadingError(Exception):
    pass

class AbstractPolicyDirectoryLoader:
    def __init__(self, policy_path):
        logging.debug('AbstractPolicyDirectoryLoader(policy_path=%r)',
            policy_path)
        if not policy_path.is_dir():
            raise ValueError('path is not a directory')
        self.policy_path = policy_path

        for filepath in self.walk_files():
            self.handle_file(filepath)

    def walk_files(self, *, path=None, in_include=False):
        if path is None:
            path = self.policy_path
        for filepath in path.iterdir():
            if filepath.is_dir():
                if in_include or filepath.name != 'include':
                    raise PolicyDirectoryLoadingError(
                        'found unexpected directory {}'.format(filepath))
                yield from self.walk_files(path=filepath, in_include=True)
                continue
            if not filepath.is_file():
                raise PolicyDirectoryLoadingError(
                    'found {} which is not a file'.format(filepath))
            yield filepath

    def handle_file(self, filepath):
        raise NotImplementedError()

class Toposorter(AbstractPolicyDirectoryLoader):
    @enum.unique
    class State(enum.Enum):
        ON_PATH, IN_ORDER = object(), object()

    def __init__(self, *args, **kwds):
        self.parsers = {}
        super().__init__(*args, **kwds)

        self.order = []
        self.queue = set(self.parsers.values())
        while self.queue:
            self.dfs(self.queue.pop())

        del self.parsers

    def handle_file(self, filepath):
        logging.debug('Toposorter.handle_file(filepath=%r)', filepath)
        self.parsers[str(filepath.relative_to(self.policy_path))] = ToposortParser(
            filepath=filepath,
            policy_path=self.policy_path)

    def dfs(self, node):
        node.state = self.State.ON_PATH

        for path in node.included_paths:
            nextnode = self.parsers[path]
            if nextnode.state == self.State.ON_PATH:
                raise ValueError('circular include; {} → {}'.format(
                    node.filepath, nextnode.filepath))
            if nextnode.state == self.State.IN_ORDER:
                continue

            self.queue.discard(nextnode)
            self.dfs(nextnode)

        self.order.append(node)
        node.state = self.State.IN_ORDER

def toposort(path):
    '''Given path to a directory, yield (file, filename) in order suitable for
    mass-uploading.

    A file does not include anything from any file that follows in the
    sequence.

    *file* is an open()'d file for reading, *filename* is relative to *path*
    '''
    # TODO allow for different loader, like from backup, zipfile or whatever
    path = path.resolve()
    for parser in Toposorter(path).order:
        yield (parser.file, str(parser.filepath.relative_to(path)))
