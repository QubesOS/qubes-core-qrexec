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

'''Qrexec policy parser and evaluator'''

import abc
import collections
import enum
import inspect
import io
import itertools
import logging
import pathlib
import string
import subprocess

from .. import QREXEC_CLIENT, POLICYPATH
from .. import exc
from .. import utils
from ..exc import (
    AccessDenied, PolicySyntaxError, PolicyNotFound, QubesMgmtException)

FILENAME_ALLOWED_CHARSET = set(string.digits + string.ascii_lowercase + '_.-')

def verify_filename(filepath):
    filepath = pathlib.Path(filepath)
    return (set(filepath.name).issubset(FILENAME_ALLOWED_CHARSET)
        and not filepath.name.startswith('.'))

def validate_service_and_argument(service, argument, *, filepath, lineno):
    # TODO maybe validate charset?

    if service == '*':
        service = None

    if argument == '*':
        argument = None
    else:
        if not argument.startswith('+'):
            raise PolicySyntaxError(filepath, lineno,
                'argument {!r} does not start with +'.format(argument))

        if service is None:
            raise PolicySyntaxError(filepath, lineno,
                'only * argument allowed for * service')

    return service, argument


class VMTokenMeta(abc.ABCMeta):
    exacts = collections.OrderedDict()
    prefixes = collections.OrderedDict()
    def __init__(cls, name, bases, dict_):
        super().__init__(name, bases, dict_)

        assert not ('EXACT' in dict_ and 'PREFIX' in dict_)
        if 'EXACT' in dict_:
            cls.exacts[dict_['EXACT']] = cls
        if 'PREFIX' in dict_:
            cls.prefixes[dict_['PREFIX']] = cls

class VMToken(str, metaclass=VMTokenMeta):
    '''A domain specification

    Wherever policy evaluation needs to represent a VM or a ``@something``
    token, instances of this class (and subclasses) are used. Each ``@token``
    has its own dedicated class.

    There are 4 such contexts:
        - :py:class:`Source` for whatever was specified in policy in 3rd column
        - :py:class:`Target` 4th column in policy
        - :py:class:`Redirect` ``target=`` parameter to :py:class:`Allow` and
          :py:class:`Ask`
        - :py:class:`IntendedTarget` for what **user** invoked the call for

    Not all ``@tokens`` can be used everywhere. Where they can be used is
    specified by inheritance.
    '''
    def __new__(cls, token, *, filepath=None, lineno=None):
        # first, adjust some aliases
        if token == 'dom0':
            # TODO: log a warning in Qubes 4.1
            token = '@adminvm'

        # if user specified just qube name, use it directly
        if not token.startswith('@'):
            return super().__new__(cls, token)

        # token starts with @, we search for right subclass
        for exact, c in cls.exacts.items():
            if not issubclass(c, cls):
                # the class has to be our subclass, that's how we define which
                # tokens can be used where
                continue
            if token == exact:
                return super().__new__(c, token)

        # for prefixed tokens, we pass just suffixes
        for prefix, c in cls.prefixes.items():
            if not issubclass(c, cls):
                continue
            if token.startswith(prefix):
                value = token[len(prefix):]
                if not value:
                    raise PolicySyntaxError(filepath, lineno,
                        'invalid empty {} token: {!r}'.format(prefix, token))
                if value.startswith('@'):
                    # we are either part of a longer prefix (@dispvm:@tag: etc),
                    # or the token is invalid, in which case this will fallthru
                    continue
                return super().__new__(c, token)

        # the loop didn't find any valid prefix, so this is not a valid token
        raise PolicySyntaxError(filepath, lineno,
            'invalid {} token: {!r}'.format(cls.__name__.lower(), token))

    def __init__(self, token, *, filepath=None, lineno=None):
        super().__init__()
        self.filepath = filepath
        self.lineno = lineno
        try:
            self.value = self[len(self.PREFIX):]
            assert self.value[0] != '@'
        except AttributeError:
            #self.value = self
            pass

#   def __repr__(self):
#       return '<{} value={!r} filepath={} lineno={}>'.format(
#           type(self).__name__, str(self), self.filepath, self.lineno)

    # This replaces is_match() and is_match_single().
    def match(self, other, *, system_info, source=None):
        return self == other

    def is_special_value(self):
        '''Check if the token specification is special (keyword) value
        '''
        return self.startswith('@')

    @property
    def type(self):
        return 'keyword' if self.is_special_value() else 'name'

class Source(VMToken):
    pass

class Target(VMToken):
    def expand(self, *, system_info):
        '''An iterator over all valid domain names that this token would match

        This is used as part of :py:meth:`Policy.collect_targets_for_ask()`.
        '''
        if self in system_info['domains']:
            yield IntendedTarget(self)

class Redirect(VMToken):
    def __new__(cls, value, *, filepath=None, lineno=None):
        if value is None:
            return value
        return super().__new__(cls, value, filepath=filepath, lineno=lineno)

# this method (with overloads in subclasses) was verify_target_value
class IntendedTarget(VMToken):
    def verify(self, *, system_info):
        '''Check if given value names valid target

        This function check if given value is not only syntactically correct,
        but also if names valid service call target (existing domain, or valid
        @dispvm like keyword)

        :param system_info: information about the system
        '''
        # for subclass it has to be overloaded
        # pylint: disable=unidiomatic-typecheck
        if type(self) != IntendedTarget:
            raise NotImplementedError()

        if self not in system_info['domains']:
            raise AccessDenied('invalid target: {}'.format(str.__repr__(self)))

        return self

# And the tokens. Inheritance defines, where the token can be used.

class AdminVM(Target, Redirect, IntendedTarget):
    # no Source: for calls originating from AdminVM policy is not evaluated
    EXACT = '@adminvm'
#   def match(self, other, *, system_info, source=None):
#       return self == other
    def expand(self, *, system_info):
        yield self
    def verify(self, *, system_info):
        return self

class AnyVM(Source, Target):
    EXACT = '@anyvm'
    def match(self, other, *, system_info, source=None):
        return other != '@adminvm'
    def expand(self, *, system_info):
        for name, domain in system_info['domains'].items():
            if name != 'dom0':
                yield IntendedTarget(name)
            if domain['template_for_dispvms']:
                yield DispVMTemplate('@dispvm:' + name)
        yield DispVM('@dispvm')

class DefaultVM(Target, IntendedTarget):
    EXACT = '@default'
#   def match(self, other, *, system_info, source=None):
#       return self == other
    def expand(self, *, system_info):
        yield from ()
    def verify(self, *, system_info):
        return self

class TypeVM(Source, Target):
    PREFIX = '@type:'
    def match(self, other, *, system_info, source=None):
        return (other in system_info['domains']
            and self.value == system_info['domains'][other]['type'])
    def expand(self, *, system_info):
        for name, domain in system_info['domains'].items():
            if domain['type'] == self.value:
                yield IntendedTarget(name)

class TagVM(Source, Target):
    PREFIX = '@tag:'
    def match(self, other, *, system_info, source=None):
        return (other in system_info['domains']
            and self.value in system_info['domains'][other]['tags'])
    def expand(self, *, system_info):
        for name, domain in system_info['domains'].items():
            if self.value in domain['tags']:
                yield IntendedTarget(name)

class DispVM(Target, Redirect, IntendedTarget):
    EXACT = '@dispvm'
    def match(self, other, *, system_info, source=None):
        return self == other
    def expand(self, *, system_info):
        yield self
    def verify(self, *, system_info):
        return self
    def get_dispvm_template(self, source, *, system_info):
        if (source not in system_info['domains']
                or system_info['domains'][source]['default_dispvm'] is None):
            return None
        return DispVMTemplate(
            '@dispvm:' + system_info['domains'][source]['default_dispvm'])

class DispVMTemplate(Source, Target, Redirect, IntendedTarget):
    PREFIX = '@dispvm:'
    def match(self, other, *, system_info, source=None):
        if isinstance(other, DispVM):
            return self == other.get_dispvm_template(source,
                system_info=system_info)
        return self == other

    def expand(self, *, system_info):
        if system_info['domains'][self.value]['template_for_dispvms']:
            yield self
        # else: log a warning?

    def verify(self, *, system_info):
        if (self.value not in system_info['domains']
        or not system_info['domains'][self.value]['template_for_dispvms']):
            raise AccessDenied(
                'not a template for dispvm: {}'.format(self.value))
        return self

class DispVMTag(Source, Target):
    PREFIX = '@dispvm:@tag:'
    def match(self, other, *, system_info, source=None):
        if isinstance(other, DispVM):
            other = other.get_dispvm_template(source, system_info=system_info)

        if not isinstance(other, DispVMTemplate):
            # 1) original other may have been neither @dispvm:<name> nor @dispvm
            # 2) other.get_dispvm_template() may have been None
            return False

        domain = system_info['domains'][other.value]
        if not domain['template_for_dispvms']:
            return False
        if not self.value in domain['tags']:
            return False

        return True

    def expand(self, *, system_info):
        for name, domain in system_info['domains'].items():
            if self.value in domain['tags'] and domain['template_for_dispvms']:
                yield DispVMTemplate('@dispvm:' + name)

#
# resolutions
#

class AbstractResolution(metaclass=abc.ABCMeta):
    '''Object representing positive policy evaluation result -
    either ask or allow action '''

    def __init__(self, rule, request, *, user):

        #: policy rule from which this action is derived
        self.rule = rule
        #: request
        self.request = request
        #: the user to run command as, or None for default
        self.user = user

    @abc.abstractmethod
    def execute(self, caller_ident, *, system_info):
        raise NotImplementedError()

class AllowResolution(AbstractResolution):
    def __init__(self, *args, actual_target, **kwds):
        super().__init__(*args, **kwds)
        #: target domain the service should be connected to, None if
        # not chosen yet
        self.actual_target = actual_target

    @classmethod
    def from_ask_resolution(cls, ask_resolution, *, actual_target):
        return cls(
            ask_resolution.rule,
            ask_resolution.request,
            user=ask_resolution.user,
            actual_target=actual_target)

    def execute(self, caller_ident, *, system_info):
        '''Execute allowed service call

        :param caller_ident: Service caller ident
            (`process_ident,source_name, source_id`)
        '''
        assert self.actual_target is not None

        target = self.actual_target

        if target == '@adminvm':
            cmd = ('QUBESRPC {request.service} {request.source} '
                    '{request.target.type} {request.target}').format(
                request=self.request)
        else:
            cmd = '{user}:QUBESRPC {request.service} {request.source}'.format(
                user=(self.user or 'DEFAULT'), request=self.request)

        if target.startswith('@dispvm:'):
            target = self.spawn_dispvm()
            dispvm = True
        else:
            self.ensure_target_running()
            dispvm = False

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
        assert isinstance(self.actual_target, DispVMTemplate)
        base_appvm = self.actual_target.value
        dispvm_name = utils.qubesd_call(base_appvm, 'admin.vm.CreateDisposable')
        dispvm_name = dispvm_name.decode('ascii')
        utils.qubesd_call(dispvm_name, 'admin.vm.Start')
        return IntendedTarget(dispvm_name)

    def ensure_target_running(self):
        '''
        Start domain if not running already

        :return: None
        '''
        if self.actual_target == '@adminvm':
            return
        try:
            utils.qubesd_call(self.actual_target, 'admin.vm.Start')
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
        utils.qubesd_call(dispvm, 'admin.vm.Kill')

class AskResolution(AbstractResolution):
    def __init__(self, *args, targets_for_ask, default_target, **kwds):
        super().__init__(*args, **kwds)
        assert default_target is None or default_target in targets_for_ask

        #: targets for the user to choose from
        self.targets_for_ask = targets_for_ask
        self.default_target = default_target

    def handle_user_response(self, response, target):
        '''
        Handle user response for the 'ask' action

        :param response: whether the call was allowed or denied (bool)
        :param target: target chosen by the user (if reponse==True)
        :return: None
        '''
        # pylint: disable=redefined-variable-type
        if not response:
            raise AccessDenied('denied by the user {}:{}'.format(
                self.rule.filepath, self.rule.lineno))

        assert target in self.targets_for_ask
        return self.request.allow_resolution_type.from_ask_resolution(self,
            actual_target=target)

    def execute(self, caller_ident, *, system_info):
        raise AccessDenied('denied for non-interactive ask')

#
# request
#

class Request:
    def __init__(self, service, argument, source, target, *, system_info,
            allow_resolution_type=AllowResolution,
            ask_resolution_type=AskResolution):

        if target == '':
            target = '@default'
        assert argument and argument[0] == '+'

        self.service = service
        self.argument = argument
        self.source = source
        self.target = IntendedTarget(target).verify(system_info=system_info)

        self.system_info = system_info
        self.allow_resolution_type = allow_resolution_type
        self.ask_resolution_type = ask_resolution_type

#
# actions
#

class ActionType(metaclass=abc.ABCMeta):
    def __init__(self, rule):
        self.rule = rule

    @abc.abstractmethod
    def evaluate(self, request):
        raise NotImplementedError()

class Deny(ActionType):
    def __repr__(self):
        return '<{}>'.format(type(self).__name__)

    def evaluate(self, request):
        raise AccessDenied('denied by policy {}:{}'.format(
            self.rule.filepath, self.rule.lineno))

class Allow(ActionType):
    def __init__(self, *args, target=None, user=None, **kwds):
        super().__init__(*args, **kwds)
        self.target = Redirect(target,
            filepath=self.rule.filepath, lineno=self.rule.lineno)
        self.user = user

    def __repr__(self):
        return '<{} target={!r} user={!r}>'.format(
            type(self).__name__, self.target, self.user)

    def actual_target(self, intended_target):
        '''If action has redirect, it is it. Otherwise, the rule's own target'''
        return self.target or intended_target

    def evaluate(self, request):
        target = self.actual_target(request.target).verify(
            system_info=request.system_info)
        if target == '@default':
            raise AccessDenied(
                'policy define \'allow\' action at {}:{} but no target is '
                'specified by caller or policy'.format(
                    self.rule.filepath, self.rule.lineno))
        if target == '@dispvm':
            target = self.rule.actual_target.get_dispvm_template(
                self.rule.source, system_info=request.system_info)
            if target is None:
                raise AccessDenied(
                    'policy define \'allow\' action to @dispvm at {}:{} '
                    'but no DispVM base is set for this VM'.format(
                        self.rule.filepath, self.rule.lineno))

        return request.allow_resolution_type(self.rule, request,
            user=self.user, actual_target=target)

class Ask(ActionType):
    def __init__(self, *args, target=None, default_target=None, user=None,
            **kwds):
        super().__init__(*args, **kwds)
        self.target = Redirect(target,
            filepath=self.rule.filepath, lineno=self.rule.lineno)
        self.default_target = Redirect(default_target,
            filepath=self.rule.filepath, lineno=self.rule.lineno)
        self.user = user

    def __repr__(self):
        return '<{} target={!r} default_target={!r} user={!r}>'.format(
            type(self).__name__, self.target, self.default_target, self.user)

    def evaluate(self, request):
        assert self.rule.is_match(request)

        if self.rule.action.target is not None:
            targets_for_ask = [request.target]
        else:
            targets_for_ask = list(self.rule.policy.collect_targets_for_ask(
                request))

        if not targets_for_ask:
            raise AccessDenied(
                'policy define \'ask\' action at {}:{} but no target is '
                'available to choose from'.format(
                    self.rule.filepath, self.rule.lineno))

        return request.ask_resolution_type(self.rule, request,
            user=self.user, targets_for_ask=targets_for_ask,
            default_target=self.default_target or request.target)

@enum.unique
class Action(enum.Enum):
    '''Action as defined by policy'''
    allow = Allow
    deny = Deny
    ask = Ask

class Rule(object):
    '''A single line of policy file

    Use
    '''
    # pylint: disable=too-many-instance-attributes

    def __init__(self, service, argument, source, target, action, params,
            *, policy, filepath, lineno):
        self.policy = policy
        self.lineno = lineno
        self.filepath = filepath

        service, argument = validate_service_and_argument(
            service, argument, filepath=filepath, lineno=lineno)

        #: the qrexec service
        self.service = service
        #: the argument to the service
        self.argument = argument
        #: source specification
        self.source = Source(source, filepath=filepath, lineno=lineno)
        #: target specification
        self.target = Target(target, filepath=filepath, lineno=lineno)

        try:
            actiontype = Action[action].value
        except KeyError:
            raise PolicySyntaxError(filepath, lineno,
                'invalid action: {}'.format(action))

        kwds = {}
        for param in params:
            try:
                key, value = param.split('=', maxsplit=1)
            except ValueError:
                raise PolicySyntaxError(filepath, lineno,
                    'invalid action parameter syntax: {}'.format(param))
            if key in kwds:
                raise PolicySyntaxError(filepath, lineno,
                    'parameter given twice: {!r}'.format(key))
            kwds[key] = value
        try:
            #: policy action
            self.action = actiontype(rule=self, **kwds)
        except TypeError:
            raise PolicySyntaxError(filepath, lineno,
                'invalid parameters for action {}: {}'.format(
                    actiontype.__name__, params))

        # verify special cases
        if (isinstance(self.target, DefaultVM)
        and isinstance(self.action, Allow)
        and self.action.target is None):
            raise PolicySyntaxError(filepath, lineno,
                'allow action for @default rule must specify target= option')


    def __repr__(self):
        return ('<{} service={!r} argument={!r}'
                ' source={!r} target={!r} action={!r}>'.format(
                    type(self).__name__, self.service, self.argument,
                    self.source, self.target, self.action))

    @classmethod
    def from_line(cls, policy, line, *, filepath, lineno):
        '''
        Load a single line of qrexec policy and check its syntax.
        Do not verify existence of named objects.

        :raise PolicySyntaxError: when syntax error is found

        :param line: a single line of actual qrexec policy (not a comment,
        empty line or @include)
        :param pathlib.Path filepath: Path of the file from which this line is
            loaded
        :param lineno: line number from which this line is loaded
        '''

        try:
            service, argument, source, target, action, *params = line.split()
        except ValueError:
            raise PolicySyntaxError(filepath, lineno, 'wrong number of fields')

        return cls(service, argument, source, target, action, params,
            policy=policy, filepath=filepath, lineno=lineno)

    @classmethod
    def from_line_service(cls, policy, service, argument, line, *,
            filepath, lineno):

        try:
            source, target, action, *params = line.split()
        except ValueError:
            raise PolicySyntaxError(filepath, lineno, 'wrong number of fields')

        params = tuple(itertools.chain(*(p.split(',') for p in params)))

        return cls(service, argument, source, target, action, params,
            policy=policy, filepath=filepath, lineno=lineno)

    def is_match(self, request):
        '''Check if given (service, argument source, target) matches this line.

        :param system_info: information about the system - available VMs,
            their types, labels, tags etc. as returned by
            :py:func:`app_to_system_info`
        :param service: name of the service
        :param argument: the argument
        :param source: name of the source VM
        :param target: name of the target VM, or None if not specified
        :param system_info: the context
        :return: True or False
        '''

        return (self.is_match_but_target(request)
            and self.target.match(request.target, source=request.source,
                system_info=request.system_info))

    def is_match_but_target(self, request):
        '''Check if given (service, argument source) matches this line.

        Target is ignored. This is used for :py:meth:`collect_targets_for_ask`.

        :param system_info: information about the system - available VMs,
            their types, labels, tags etc. as returned by
            :py:func:`app_to_system_info`
        :param service: name of the service
        :param argument: the argument
        :param source: name of the source VM
        :param target: name of the target VM, or None if not specified
        :param system_info: the context
        :return: True or False
        '''

        return ((self.service is None or self.service == request.service)
            and (self.argument is None or self.argument == request.argument)
            and self.source.match(request.source,
                    system_info=request.system_info))


class AbstractPolicyParser(metaclass=abc.ABCMeta):
    '''A minimal, pluggable, validating policy parser'''
    rule_type = Rule

    @staticmethod
    def resolve_file_and_filepath(file, filepath):
        if filepath is None:
            if isinstance(file, (str, pathlib.Path)):
                filepath = pathlib.Path(file)
                file = filepath.open()
            else:
                try:
                    filepath = pathlib.Path(file.name)
                except AttributeError:
                    pass
        else:
            filepath = pathlib.Path(filepath)
        return file, filepath

    def load_policy_file(self, file, filepath=None):
        '''Parse a policy file'''
        file, filepath = self.resolve_file_and_filepath(file, filepath)

        for lineno, line in enumerate(file, start=1):
            line = line.strip()

            # skip empty lines and comments
            if not line or line[0] == '#':
                continue

            if line.startswith('!'):
                directive, *params = line.split()

                if directive == '!include':
                    self.handle_include(*params,
                        filepath=filepath, lineno=lineno)
                    continue
                if directive == '!include-dir':
                    self.handle_include_dir(*params,
                        filepath=filepath, lineno=lineno)
                    continue
                if directive == '!include-service':
                    self.handle_include_service(*params,
                        filepath=filepath, lineno=lineno)
                    continue

                raise PolicySyntaxError(filepath, lineno, 'invalid directive')

            # this can raise PolicySyntaxError on its own
            self.handle_rule(self.rule_type.from_line(self, line,
                filepath=filepath, lineno=lineno),
                filepath=filepath, lineno=lineno)

        return self

    def load_policy_file_service(self, service, argument, file,
            filepath=None):
        '''Parse a policy file from ``!include-service``'''
        file, filepath = self.resolve_file_and_filepath(file, filepath)

        for lineno, line in enumerate(file, start=1):
            line = line.strip()

            # skip empty lines and comments
            if not line or line[0] == '#':
                continue

            line = line.replace('$include:', '!include ')
            line = line.replace('$', '@')

            if line.startswith('!'):
                directive, *params = line.split()

                if directive == '!include':
                    self.handle_include_service(service, argument, *params,
                        filepath=filepath, lineno=lineno)
                    continue

                raise PolicySyntaxError(filepath, lineno, 'invalid directive')

            # this can raise PolicySyntaxError on its own
            self.handle_rule(self.rule_type.from_line_service(self,
                    service, argument, line, filepath=filepath, lineno=lineno),
                filepath=filepath, lineno=lineno)

        return self

    @abc.abstractmethod
    def handle_include(self, included_path, *, filepath, lineno):
        '''Handle ``!include`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_include_dir(self, included_path, *, filepath, lineno):
        '''Handle ``!include-dir`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_include_service(self, service, argument, included_path, *,
            filepath, lineno):
        '''Handle ``!include-service`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_rule(self, rule, *, filepath, lineno):
        '''Handle a line with a rule.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()

class AbstractFilePolicy(AbstractPolicyParser):
    # pylint: disable=abstract-method
    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        #: list of Rule objects
        self.policy_rules = []

    def handle_include(self, included_path, *, filepath, lineno):
        # pylint: disable=unused-argument
        assert filepath is not None
        included_path = (filepath.resolve().parent / included_path).resolve()
        if not included_path.is_file():
            raise exc.PolicySyntaxError(filepath, lineno,
                'not a file: {}'.format(included_path))
        self.load_policy_file(included_path)

    def handle_include_service(self, service, argument, included_path, *,
            filepath, lineno):
        service, argument = validate_service_and_argument(
            service, argument, filepath=filepath, lineno=lineno)
        included_path = (filepath.resolve().parent / included_path).resolve()
        self.load_policy_file_service(service, argument, included_path)

    def handle_rule(self, rule, *, filepath, lineno):
        # pylint: disable=unused-argument
        self.policy_rules.append(rule)

    def find_matching_rule(self, request):
        '''Find the first rule matching given arguments'''

        for rule in self.policy_rules:
            if rule.is_match(request):
                return rule
        raise AccessDenied('no matching rule found')

    def evaluate(self, request):
        '''Evaluate policy

        :raise AccessDenied: when action should be denied unconditionally

        :return tuple(rule, considered_targets) - where considered targets is a
        list of possible targets for 'ask' action (rule.action == Action.ask)
        '''

        rule = self.find_matching_rule(request)
        return rule.action.evaluate(request)

    def collect_targets_for_ask(self, request):
        '''Collect targets the user can choose from in 'ask' action

        Word 'targets' is used intentionally instead of 'domains', because it
        can also contains @dispvm like keywords.
        '''
        targets = set()

        # iterate over rules in reversed order to easier handle 'deny'
        # actions - simply remove matching domains from allowed set
        for rule in reversed(self.policy_rules):
            if rule.is_match_but_target(request):
                expansion = set((rule.action.target or rule.target).expand(
                    system_info=request.system_info))
                if isinstance(rule.action, Action.deny.value):
                    targets -= expansion
                else:
                    targets.update(expansion)

        # expand default DispVM
        if '@dispvm' in targets:
            targets.remove('@dispvm')
            dispvm = DispVM('@dispvm').get_dispvm_template(request.source,
                system_info=request.system_info)
            if dispvm is not None:
                targets.add(dispvm)

        # expand other keywords
        if '@adminvm' in targets:
            targets.remove('@adminvm')
            targets.add('dom0')

        return targets

class FilePolicy(AbstractFilePolicy):
    '''Full policy for a given service

    Usage:
    >>> system_info = get_system_info()
    >>> policy = Policy()
    >>> action = policy.evaluate(system_info, 'source-name', 'target-name')
    >>> if action.action == Action.ask:
    >>>     # ... ask the user, see action.targets_for_ask ...
    >>>     action.handle_user_response(response, target_chosen_by_user)
    >>> action.execute('process-ident')
    '''

    def __init__(self, *, policy_path=POLICYPATH):
        super().__init__()
        self.policy_path = pathlib.Path(policy_path)

        try:
            self.load_policy_dir(self.policy_path)
        except OSError as err:
            raise AccessDenied(
                'failed to load {} file: {!s}'.format(err.filename, err))

    def handle_include_dir(self, included_path, *, filepath, lineno):
        # pylint: disable=unused-argument
        assert filepath is not None
        included_path = (filepath.resolve().parent / included_path).resolve()
        if not included_path.is_dir():
            raise exc.PolicySyntaxError(filepath, lineno,
                'not a directory: {}'.format(included_path))
        self.load_policy_dir(included_path)

    def load_policy_dir(self, dirpath):
        # check for invalid filenames first, then iterate
        paths = [path for path in dirpath.iterdir()
            if path.is_file() and not path.name.startswith('.')]
        for path in paths:
            if not verify_filename(path):
                raise exc.AccessDenied('invalid filename: {}'.format(path))

        paths.sort()

        for path in paths:
            self.load_policy_file(path)

class TestPolicy(AbstractPolicyParser):
    def __init__(self, *args, policy, **kwds):
        super().__init__(*args, **kwds)
        caller = inspect.stack()[1]
        self.load_policy_file(io.StringIO(policy),
            filepath='{}+{}'.format(caller.filename, caller.lineno))

    def handle_include_dir(self, included_path, *, filepath, lineno):
        raise NotImplementedError(
            '!include-dir is unsupported in {}'.format(type(self).__name__))


class ValidateIncludesParser(AbstractPolicyParser):
    '''A parser that checks if included file does indeed exist.

    The included file is not read, because if it exists, it is assumed it
    already passed syntax check.
    '''
    def handle_include(self, included_path, *, filepath, lineno):
        # TODO disallow anything other that @include:[include/]<file>
        included_path = (filepath.resolve().parent / included_path).resolve()
        if not included_path.is_file():
            raise PolicySyntaxError(filepath, lineno,
                'included path {!s} does not exist'.format(included_path))

    def handle_include_service(self, service, argument, included_path, *,
            filepath, lineno):
        # TODO disallow anything other that @include:[include/]<file>
        included_path = (filepath.resolve().parent / included_path).resolve()
        if not included_path.is_file():
            raise PolicySyntaxError(filepath, lineno,
                'included path {!s} does not exist'.format(included_path))

    def handle_include_dir(self, included_path, *, filepath, lineno):
        included_path = (filepath.resolve().parent / included_path).resolve()
        if not included_path.is_dir():
            raise PolicySyntaxError(filepath, lineno,
                'included path {!s} does not exist'.format(included_path))

    def handle_rule(self, rule, *, filepath, lineno):
        pass

class CheckIfNotIncludedParser(AbstractPolicyParser):
    '''A parser that checks if a particular file is *not* included.

    This is used while removing a particular file, to check that it is not used
    anywhere else.
    '''
    def __init__(self, *args, to_be_removed, **kwds):
        self.to_be_removed = self.policy_path / to_be_removed
        super().__init__(*args, **kwds)

    def handle_include(self, included_path, *, filepath, lineno):
        included_path = self.policy_path / included_path
        if included_path.samefile(self.to_be_removed):
            raise PolicySyntaxError(filepath, lineno,
                'included path {!s}'.format(included_path))

    def handle_rule(self, rule, *, filepath, lineno):
        pass

class ToposortParser(AbstractFilePolicy):
    '''A helper for topological sorting the policy files'''

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self.included_paths = set()
        self.state = None

    def handle_include(self, included_path, filepath, lineno):
        logging.debug('ToposortParser(filepath=%r).handle_include(included_path=%r)',
            self.filepath, included_path)
        if '/' in included_path and (
                not included_path.startswith('include/')
                or included_path.count('/') > 1):
            # TODO make this an error, since we shouldn't accept this anyway
            logging.warning('ignoring path %r included in %s on line %d; '
                'expect problems with import order',
                included_path, filepath, lineno)
            return
        self.included_paths.add(included_path)

    def handle_rule(self, rule, filepath, lineno):
        pass

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
