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

# pylint: disable=too-many-lines

'''Qrexec policy parser and evaluator'''

import abc
import collections
import collections.abc
import enum
import io
import itertools
import logging
import pathlib
import string
import asyncio

from typing import (
    Iterable,
    List,
    TextIO,
    Tuple,
)

from .. import QREXEC_CLIENT, POLICYPATH, RPCNAME_ALLOWED_CHARSET, POLICYSUFFIX
from .. import exc
from .. import utils
from ..exc import (
    AccessDenied, PolicySyntaxError, QubesMgmtException, ExecutionFailed)

FILENAME_ALLOWED_CHARSET = set(string.digits + string.ascii_lowercase + '_.-')

def filter_filepaths(filepaths: Iterable[pathlib.Path]) -> List[pathlib.Path]:
    '''Check if files should be considered by policy.

    The file name should contain only allowed characters (latin lowercase,
    digits, underscore, full stop and dash). It should not start with the dot.

    Only the file name is considered, not the directories on path that leads to
    it.

    Args:
        filepaths: the file paths
    Returns:
        list of pathlib.Path: sorted list of paths, without ignored ones
    Raises:
        qrexec.exc.AccessDenied: for invalid path which is not ignored
    '''
    filepaths = [path for path in filepaths
        if path.is_file() and path.suffix == POLICYSUFFIX
            and not path.name.startswith('.')]

    # check for invalid filenames first, then return all or nothing
    for path in filepaths:
        if not set(path.name).issubset(FILENAME_ALLOWED_CHARSET):
            raise exc.AccessDenied('invalid filename: {}'.format(path))

    filepaths.sort()

    return filepaths

def parse_service_and_argument(rpcname, *, no_arg='+'):
    '''Parse service and argument string.

    Parse ``SERVICE+ARGUMENT``. Argument may be empty (single ``+`` at the end)
    or omitted (no ``+`` at all). If no argument is given, `no_arg` is returned
    instead. By default this returns ``'+'``, as if argument is empty.

    A `Path` from :py:mod:`pathlib` is also accepted, in which case the filename
    is parsed.
    '''
    if isinstance(rpcname, pathlib.PurePath):
        rpcname = rpcname.name

    if '+' in rpcname:
        service, argument = rpcname.split('+', 1)
        argument = '+' + argument
    else:
        service, argument = rpcname, no_arg
    return service, argument

def get_invalid_characters(s, allowed=RPCNAME_ALLOWED_CHARSET, disallowed=''):
    '''Return characters contained in *disallowed* and/or not int *allowed*'''
    # pylint: disable=invalid-name
    return tuple(sorted(set(c for c in s
        if c not in allowed.difference(disallowed))))

def validate_service_and_argument(service, argument, *, filepath, lineno):
    '''Check service name and argument

    This is intended as policy syntax checker to discard obviously invalid
    service names and arguments. There are some cases for which this function
    will not signal a problem, but the call still would be invalid. One of those
    cases is too long total call name.

    Args:
        service (str): the service as appeared in policy file
        argument (str): the argument as appeared in policy file
        filepath (pathlib.Path): the file path
        lineno (int): the line in the file

    Returns:
        (str or None, str or None): service and argument

    Raises:
        qrexec.exc.PolicySyntaxError: for a number of forbidden cases
    '''

    if service == '*':
        service = None

    if service is not None:
        invalid_chars = get_invalid_characters(service, disallowed='+')
        if invalid_chars:
            raise PolicySyntaxError(filepath, lineno,
                'service {!r} contains invalid characters: {!r}'.format(
                    service, invalid_chars))

    if argument == '*':
        argument = None

    if argument is not None:
        invalid_chars = get_invalid_characters(argument)
        if invalid_chars:
            raise PolicySyntaxError(filepath, lineno,
                'argument {!r} contains invalid characters: {!r}'.format(
                    argument, invalid_chars))

        if not argument.startswith('+'):
            raise PolicySyntaxError(filepath, lineno,
                'argument {!r} does not start with +'.format(argument))

        if service is None:
            raise PolicySyntaxError(filepath, lineno,
                'only * argument allowed for * service')

    return service, argument


class VMTokenMeta(abc.ABCMeta):
    # pylint: disable=missing-docstring
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
        - :py:class:`Source`: for whatever was specified in policy in 3rd column
        - :py:class:`Target`: 4th column in policy
        - :py:class:`Redirect`: ``target=`` parameter to :py:class:`Allow` and
          :py:class:`Ask`, and ``default_target=`` for the latter
        - :py:class:`IntendedTarget`: for what **user** invoked the call for

    Not all ``@tokens`` can be used everywhere. Where they can be used is
    specified by inheritance.

    All tokens are also instances of :py:class:`str` and can be compared to
    other strings.
    '''
    def __new__(cls, token, *, filepath=None, lineno=None):
        orig_token = token

        # first, adjust some aliases
        if token == 'dom0':
            # TODO: log a warning in Qubes 4.1
            token = '@adminvm'

        # if user specified just qube name, use it directly
        if not token.startswith('@'):
            return super().__new__(cls, token)

        # token starts with @, we search for right subclass
        for exact, token_cls in cls.exacts.items():
            if not issubclass(token_cls, cls):
                # the class has to be our subclass, that's how we define which
                # tokens can be used where
                continue
            if token == exact:
                return super().__new__(token_cls, token)

        # for prefixed tokens, we pass just suffixes
        for prefix, token_cls in cls.prefixes.items():
            if not issubclass(token_cls, cls):
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
                return super().__new__(token_cls, token)

        # the loop didn't find any valid prefix, so this is not a valid token
        raise PolicySyntaxError(filepath, lineno,
            'invalid {} token: {!r}'.format(cls.__name__.lower(), orig_token))

    def __init__(self, token, *, filepath=None, lineno=None):
        # pylint: disable=unused-argument
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
        '''Check if this token matches opposite token'''
        # pylint: disable=unused-argument
        return self == other

    def is_special_value(self):
        '''Check if the token specification is special (keyword) value
        '''
        return self.startswith('@')

    @property
    def type(self):
        '''Type of the token

        ``'keyword'`` for special values, ``'name'`` for qube name
        '''
        return 'keyword' if self.is_special_value() else 'name'

    @property
    def text(self):
        '''Text of the token, without possibly '@' prefix '''
        return self.lstrip('@')

class Source(VMToken):
    # pylint: disable=missing-docstring
    pass

class _BaseTarget(VMToken):
    # pylint: disable=missing-docstring
    def expand(self, *, system_info):
        '''An iterator over all valid domain names that this token would match

        This is used as part of :py:meth:`Policy.collect_targets_for_ask()`.
        '''
        if self in system_info['domains']:
            yield IntendedTarget(self)

class Target(_BaseTarget):
    # pylint: disable=missing-docstring
    pass

class Redirect(_BaseTarget):
    # pylint: disable=missing-docstring
    def __new__(cls, value, *, filepath=None, lineno=None):
        if value is None:
            return value
        return super().__new__(cls, value, filepath=filepath, lineno=lineno)

# this method (with overloads in subclasses) was verify_target_value
class IntendedTarget(VMToken):
    # pylint: disable=missing-docstring
    def verify(self, *, system_info):
        '''Check if given value names valid target

        This function check if given value is not only syntactically correct,
        but also if names valid service call target (existing domain, or valid
        ``'@dispvm'`` like keyword)

        Args:
            system_info: information about the system

        Returns:
            VMToken: for successful verification

        Raises:
            qrexec.exc.AccessDenied: for failed verification
        '''
        # for subclass it has to be overloaded
        # pylint: disable=unidiomatic-typecheck
        if type(self) != IntendedTarget:
            raise NotImplementedError()

        if self not in system_info['domains']:
            raise AccessDenied('invalid target: {}'.format(str.__repr__(self)))

        return self

# And the tokens. Inheritance defines, where the token can be used.

class AdminVM(Source, Target, Redirect, IntendedTarget):
    # no Source, for calls originating from AdminVM policy is not evaluated
    # pylint: disable=missing-docstring,unused-argument
    EXACT = '@adminvm'
    def expand(self, *, system_info):
        yield self
    def verify(self, *, system_info):
        return self

class AnyVM(Source, Target):
    # pylint: disable=missing-docstring,unused-argument
    EXACT = '@anyvm'
    def match(self, other, *, system_info, source=None):
        return other != '@adminvm'
    def expand(self, *, system_info):
        for name, domain in system_info['domains'].items():
            if domain['type'] != 'AdminVM':
                yield IntendedTarget(name)
            if domain['template_for_dispvms']:
                yield DispVMTemplate('@dispvm:' + name)
        yield DispVM('@dispvm')

class DefaultVM(Target, IntendedTarget):
    # pylint: disable=missing-docstring,unused-argument
    EXACT = '@default'
    def expand(self, *, system_info):
        yield from ()
    def verify(self, *, system_info):
        return self

class TypeVM(Source, Target):
    # pylint: disable=missing-docstring,unused-argument
    PREFIX = '@type:'
    def match(self, other, *, system_info, source=None):
        return (other in system_info['domains']
            and self.value == system_info['domains'][other]['type'])
    def expand(self, *, system_info):
        for name, domain in system_info['domains'].items():
            if domain['type'] == self.value:
                yield IntendedTarget(name)

class TagVM(Source, Target):
    # pylint: disable=missing-docstring,unused-argument
    PREFIX = '@tag:'
    def match(self, other, *, system_info, source=None):
        return (other in system_info['domains']
            and self.value in system_info['domains'][other]['tags'])
    def expand(self, *, system_info):
        for name, domain in system_info['domains'].items():
            if self.value in domain['tags']:
                yield IntendedTarget(name)

class DispVM(Target, Redirect, IntendedTarget):
    # pylint: disable=missing-docstring,unused-argument
    EXACT = '@dispvm'
    def match(self, other, *, system_info, source=None):
        return self == other
    def expand(self, *, system_info):
        yield self
    def verify(self, *, system_info):
        return self

    @staticmethod
    def get_dispvm_template(source, *, system_info):
        '''Given source, get appropriate template for DispVM. Maybe None.'''
        if (source not in system_info['domains']
                or system_info['domains'][source]['default_dispvm'] is None):
            return None
        return DispVMTemplate(
            '@dispvm:' + system_info['domains'][source]['default_dispvm'])

class DispVMTemplate(Source, Target, Redirect, IntendedTarget):
    # pylint: disable=missing-docstring,unused-argument
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
    # pylint: disable=missing-docstring,unused-argument
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
        #: whether to notify the user about the action taken
        self.notify = rule.action.notify

    @abc.abstractmethod
    async def execute(self, caller_ident):
        '''
        Execute the action. For allow, this runs the qrexec. For ask, it asks
        user and then (depending on verdict) runs the call.

        Args:
            caller_ident (str): Service caller ident
                (``process_ident,source_name, source_id``)
        '''
        raise NotImplementedError()

class AllowResolution(AbstractResolution):
    '''Resolution returned for :py:class:`Rule` with :py:class:`Allow`.'''
    def __init__(self, *args, target, **kwds):
        super().__init__(*args, **kwds)
        #: target domain the service should be connected to
        self.target = target

    @classmethod
    def from_ask_resolution(cls, ask_resolution, *, target):
        '''This happens after user manually approved the call'''
        return cls(
            ask_resolution.rule,
            ask_resolution.request,
            user=ask_resolution.user,
            target=target)

    async def execute(self, caller_ident):
        '''Execute the allowed action'''
        assert self.target is not None

        # XXX remove when #951 gets fixed
        if self.request.source == self.target:
            raise AccessDenied('loopback qrexec connection not supported')

        target = self.target

        if target == '@adminvm':
            cmd = ('QUBESRPC {request.service}{request.argument} '
                   '{request.source} {request.target.type} {request.target.text}').\
                format(request=self.request)
        else:
            cmd = '{user}:QUBESRPC {request.service}{request.argument} ' \
                  '{request.source}'.format(
                       user=(self.user or 'DEFAULT'), request=self.request)

        if target.startswith('@dispvm:'):
            target = self.spawn_dispvm()
            dispvm = True
        else:
            self.ensure_target_running()
            dispvm = False

        qrexec_opts = ['-d', target, '-c', caller_ident, '-E']
        if dispvm:
            qrexec_opts.append('-W')
        try:
            command = [QREXEC_CLIENT] + qrexec_opts + [cmd]
            process = await asyncio.create_subprocess_exec(*command)
            await process.communicate()
        finally:
            if dispvm:
                self.cleanup_dispvm(target)
        if process.returncode != 0:
            raise ExecutionFailed('qrexec-client failed: {}'.format(command))

    def spawn_dispvm(self):
        '''
        Create and start Disposable VM based on AppVM specified in
        :py:attr:`target`.

        Returns:
            str: name of new Disposable VM
        '''
        assert isinstance(self.target, DispVMTemplate)
        base_appvm = self.target.value
        dispvm_name = utils.qubesd_call(base_appvm, 'admin.vm.CreateDisposable')
        dispvm_name = dispvm_name.decode('ascii')
        utils.qubesd_call(dispvm_name, 'admin.vm.Start')
        return IntendedTarget(dispvm_name)

    def ensure_target_running(self):
        '''
        Start domain if not running already

        Returns:
            None
        '''
        if self.target == '@adminvm':
            return
        try:
            utils.qubesd_call(self.target, 'admin.vm.Start')
        except QubesMgmtException as err:
            if err.exc_type == 'QubesVMNotHaltedError':
                pass
            else:
                raise

    @staticmethod
    def cleanup_dispvm(dispvm):
        '''
        Kill and remove Disposable VM

        Args:
            dispvm (str): name of Disposable VM

        Returns:
            None
        '''
        utils.qubesd_call(dispvm, 'admin.vm.Kill')

class AskResolution(AbstractResolution):
    '''Resolution returned for :py:class:`Rule` with :py:class:`Ask`.

    This base class is a dummy implementation which behaves as if user always
    denied the call. The programmer is expected to inherit from this class and
    overload :py:meth:`execute` to display the question to the user by
    appropriate means. User should have choice among :py:attr:`targets_for_ask`.
    If :py:attr:`default_target` is not :py:obj:`None`, that should be the
    default. Otherwise there should be no default. After querying the user,
    :py:meth:`handle_user_response` should be called. For negative answers,
    raising :py:class:`qrexec.exc.AccessDenied` is also enough.

    The child class should be supplied as part of :py:class:`Request`.
    '''
    def __init__(self, *args, targets_for_ask, default_target, **kwds):
        super().__init__(*args, **kwds)
        assert default_target is None or default_target in targets_for_ask

        #: targets for the user to choose from
        self.targets_for_ask = targets_for_ask

        #: default target, or None
        self.default_target = default_target

    def handle_user_response(self, response, target):
        '''
        Handle user response for the 'ask' action. Children class'
        :py:meth:`execute` is supposed to call this method to report the
        user's verdict.

        Args:
            response (bool): whether the call was allowed or denied
            target (str): target chosen by the user (if reponse==True)

        Returns:
            AllowResolution: for positive answer

        Raises:
            qrexec.exc.AccessDenied: for negative answer
        '''
        # pylint: disable=redefined-variable-type
        if not response:
            raise AccessDenied('denied by the user {}:{}'.format(
                self.rule.filepath, self.rule.lineno),
                notify=self.notify)

        if target not in self.targets_for_ask:
            raise AccessDenied(
                'target {} is not a valid choice'.format(target))

        return self.request.allow_resolution_type.from_ask_resolution(self,
            target=target)

    def handle_invalid_response(self):
        '''
        Handle invalid response for the 'ask' action. Throws AccessDenied.
        '''
        # pylint: disable=no-self-use
        raise AccessDenied('invalid response')

    async def execute(self, caller_ident):
        '''Ask the user for permission.

        This method should be overloaded in children classes. This
        implementation always denies the request.

        Raises:
            qrexec.exc.AccessDenied: always
        '''
        raise AccessDenied('denied for non-interactive ask')

#
# request
#
#pylint: disable=too-many-instance-attributes
class Request:
    '''Qrexec request

    A request object keeps what is searched for in the policy. It keeps the
    principal quadruple: service, argument, source and target that are
    parameters of the qrexec call. There is also `system_info`, which represents
    current state of the system, incl. the list of all domains in the system and
    their respective properties that are relevant to policy.

    Args:
        service (str or None): Service name.
        argument (str): The argument. Must start with ``'+'``.
        source (str): name of source qube
        target (str): target designation
        system_info (dict): as returned from
            :py:func:`qrexec.utils.system_info()`
        allow_resolution_type (type): a child of :py:class:`AllowResolution`
        ask_resolution_type (type): a child of :py:class:`AskResolution`
    '''

    def __init__(self, service, argument, source, target, *, system_info,
            allow_resolution_type=AllowResolution,
            ask_resolution_type=AskResolution):

        if target == '':
            target = '@default'
        assert argument and argument[0] == '+'

        #: the service that is being requested
        self.service = service
        #: argument for the service
        self.argument = argument
        #: source qube name
        self.source = source
        #: target (qube or token) as requested by source qube
        self.target = IntendedTarget(target).verify(system_info=system_info)

        #: system info
        self.system_info = system_info
        #: factory for allow resolution
        self.allow_resolution_type = allow_resolution_type
        #: factory for ask resolution
        self.ask_resolution_type = ask_resolution_type

#
# actions
#

class ActionType(metaclass=abc.ABCMeta):
    '''Base class for actions

    Children of this class are types of objects representing action in policy
    rule (:py:attr:`Rule.action`). Not to be confused with
    :py:class:`AbstractResolution`, which happens when particular rule is
    matched to a :py:class:`Request`.

    Keyword arguments to __init__ are taken from parsing params in the rule, so
    this defines, what params are valid for which action.
    '''
    def __init__(self, rule):
        #: the rule that holds this action
        self.rule = rule
        self.target = None

    @abc.abstractmethod
    def evaluate(self, request):
        '''Evaluate the request.

        Depending on action and possibly user's decision either return
        a resolution or raise exception.

        Args:
            request (Request): the request that was matched to the rule

        Returns:
            AbstractResolution: for successful requests

        Raises:
            qrexec.exc.AccessDenied: for denied requests
        '''
        raise NotImplementedError()

    def actual_target(self, intended_target):
        '''If action has redirect, it is it. Otherwise, the rule's own target

        Args:
            intended_target (IntendedTarget): :py:attr:`Request.target`

        Returns:
            IntendedTarget: either :py:attr:`target`, if not None, or
                *intended_target*
        '''
        return IntendedTarget(self.target or intended_target)

    @staticmethod
    def allow_no_autostart(target, system_info):
        '''
        Should we allow this target when autostart is disabled
        '''
        if target == '@adminvm':
            return True
        if target.startswith('@dispvm'):
            return False
        assert target in system_info['domains']
        return system_info['domains'][target]['power_state'] == 'Running'


class Deny(ActionType):
    # pylint: disable=missing-docstring
    def __init__(self, *args, notify=None, **kwds):
        super().__init__(*args, **kwds)
        self.notify = True if notify is None else notify

    def __repr__(self):
        return '<{}>'.format(type(self).__name__)

    def evaluate(self, request):
        '''
        Raises:
            qrexec.exc.AccessDenied:
        '''
        raise AccessDenied('denied by policy {}:{}'.format(
            self.rule.filepath, self.rule.lineno),
            notify=self.notify)

    def actual_target(self, intended_target):
        '''''' # not documented in HTML
        # pylint: disable=empty-docstring
        raise AccessDenied('programmer error')


class Allow(ActionType):
    # pylint: disable=missing-docstring
    def __init__(self, *args, target=None, user=None, notify=None, autostart=None, **kwds):
        super().__init__(*args, **kwds)
        self.target = Redirect(target,
            filepath=self.rule.filepath, lineno=self.rule.lineno)
        self.user = user
        self.notify = False if notify is None else notify
        self.autostart = True if autostart is None else autostart

    def __repr__(self):
        return '<{} target={!r} user={!r}>'.format(
            type(self).__name__, self.target, self.user)

    def evaluate(self, request):
        '''
        Returns:
            AllowResolution: for successful requests

        Raises:
            qrexec.exc.AccessDenied: for invalid requests
        '''
        assert self.rule.is_match(request)

        target = self.actual_target(request.target).verify(
            system_info=request.system_info)
        if target == '@default':
            raise AccessDenied(
                'policy define \'allow\' action at {}:{} but no target is '
                'specified by caller or policy'.format(
                    self.rule.filepath, self.rule.lineno))
        if target == '@dispvm':
            target = target.get_dispvm_template(  # pylint: disable=no-member
                request.source, system_info=request.system_info)
            if target is None:
                raise AccessDenied(
                    'policy define \'allow\' action to @dispvm at {}:{} '
                    'but no DispVM base is set for this VM'.format(
                        self.rule.filepath, self.rule.lineno))

        if not self.autostart and not self.allow_no_autostart(
                target, request.system_info):
            raise AccessDenied(
                'target {} is denied because it would require autostart')

        return request.allow_resolution_type(self.rule, request,
            user=self.user, target=target)


class Ask(ActionType):
    # pylint: disable=missing-docstring
    def __init__(self, *args, target=None, default_target=None, user=None,
                 notify=None, autostart=None, **kwds):
        super().__init__(*args, **kwds)
        self.target = Redirect(target,
            filepath=self.rule.filepath, lineno=self.rule.lineno)
        self.default_target = Redirect(default_target,
            filepath=self.rule.filepath, lineno=self.rule.lineno)
        self.user = user
        self.notify = False if notify is None else notify
        self.autostart = True if autostart is None else autostart

    def __repr__(self):
        return '<{} target={!r} default_target={!r} user={!r}>'.format(
            type(self).__name__, self.target, self.default_target, self.user)

    def evaluate(self, request):
        '''
        Returns:
            AskResolution

        Raises:
            qrexec.exc.AccessDenied: for invalid requests
        '''
        assert self.rule.is_match(request)

        if self.target is not None:
            targets_for_ask = [self.target]
        else:
            targets_for_ask = list(self.rule.policy.collect_targets_for_ask(
                request))

        if not self.autostart:
            targets_for_ask = [
                target for target in targets_for_ask
                if self.allow_no_autostart(target, request.system_info)
            ]

        if not targets_for_ask:
            raise AccessDenied(
                'policy define \'ask\' action at {}:{} but no target is '
                'available to choose from'.format(
                    self.rule.filepath, self.rule.lineno))

        return request.ask_resolution_type(self.rule, request,
            user=self.user, targets_for_ask=targets_for_ask,
            default_target=self.default_target)

@enum.unique
class Action(enum.Enum):
    '''Action as defined by policy'''
    allow = Allow
    deny = Deny
    ask = Ask

class Rule:
    '''A single line of policy file

    Avoid instantiating manually, use either :py:meth:`from_line()` or
    :py:meth:`from_line_service()`.
    '''
    # pylint: disable=too-many-instance-attributes

    def __init__(self, service, argument, source, target, action, params,
            *, policy, filepath, lineno):
        # pylint: disable=too-many-arguments

        #: the parser that this rule belongs to
        self.policy = policy
        #: the file path
        self.filepath = filepath
        #: the line number
        self.lineno = lineno

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
                    'invalid action parameter syntax: {!r}'.format(param))
            if key in kwds:
                raise PolicySyntaxError(filepath, lineno,
                    'parameter given twice: {!r}'.format(key))
            kwds[key] = value

        # boolean parameters
        for key in ['notify', 'autostart']:
            if key in kwds:
                if kwds[key] not in ['yes', 'no']:
                    raise PolicySyntaxError(
                        filepath, lineno,
                        "{!r} is {!r}, but can be only 'yes' or 'no'".format(
                            key, kwds[key]))
                kwds[key] = (kwds[key] == 'yes')

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

        Args:
            line: a single line of actual qrexec policy (not a comment, empty
                line or ``@include``)
            filepath (pathlib.Path): Path of the file from which this line is
                loaded
            lineno: line number from which this line is loaded

        Raises:
            PolicySyntaxError: when syntax error is found
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
        '''Load a single line in old format.

        Args:
            service: the service for which this line applies
            argument: argument for the service
            line (str): the line to be parsed
            filepath (pathlib.Path): the file from which this line was taken
            lineno (int): the line number

        Raises:
            PolicySyntaxError: when syntax error is found
        '''
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


class AbstractParser(metaclass=abc.ABCMeta):
    '''A minimal, pluggable, validating policy parser'''

    #: default rule type
    rule_type = Rule

    @staticmethod
    def _fix_filepath(file, filepath):
        if filepath is None:
            try:
                filepath = pathlib.Path(file.name)
            except AttributeError:
                if isinstance(file, io.IOBase):
                    filepath = '<buffer>'
        return file, filepath

    def load_policy_file(self, file, filepath):
        '''Parse a policy file'''
        file, filepath = self._fix_filepath(file, filepath)

        for lineno, line in enumerate(file, start=1):
            line = line.strip()

            # skip empty lines and comments
            if not line or line[0] == '#':
                self.handle_comment(line, filepath=filepath, lineno=lineno)
                continue

            if line.startswith('!'):
                directive, *params = line.split()

                if directive == '!include':
                    try:
                        included_path, = params
                    except ValueError:
                        raise PolicySyntaxError(filepath, lineno,
                            'invalid number of params')
                    self.handle_include(pathlib.PurePosixPath(included_path),
                        filepath=filepath, lineno=lineno)
                    continue
                if directive == '!include-dir':
                    try:
                        included_path, = params
                    except ValueError:
                        raise PolicySyntaxError(filepath, lineno,
                            'invalid number of params')
                    self.handle_include_dir(
                        pathlib.PurePosixPath(included_path),
                        filepath=filepath, lineno=lineno)
                    continue
                if directive == '!include-service':
                    try:
                        service, argument, included_path = params
                    except ValueError:
                        raise PolicySyntaxError(filepath, lineno,
                            'invalid number of params')
                    self.handle_include_service(service, argument,
                        pathlib.PurePosixPath(included_path),
                        filepath=filepath, lineno=lineno)
                    continue

                if directive == '!compat-4.0':
                    if params:
                        raise PolicySyntaxError(filepath, lineno,
                            'invalid number of params')
                    logging.warning(
                        'warning: !compat-4.0 directive in file %s line %s'
                        ' is transitional and will be deprecated',
                        filepath, lineno)
                    self.handle_compat40(filepath=filepath, lineno=lineno)
                    continue

                raise PolicySyntaxError(filepath, lineno, 'invalid directive')

            # this can raise PolicySyntaxError on its own
            self.handle_rule(self.rule_type.from_line(self, line,
                filepath=filepath, lineno=lineno),
                filepath=filepath, lineno=lineno)

        return self

    def load_policy_file_service(self, service, argument, file, filepath):
        '''Parse a policy file from ``!include-service``'''
        file, filepath = self._fix_filepath(file, filepath)

        for lineno, line in enumerate(file, start=1):
            line = line.strip()

            # skip empty lines and comments
            if not line or line[0] == '#':
                continue

            # compatibility substitutions, some may be unspecified and may be
            # removed in a future version
            line = line.replace('$include:', '!include ')
            line = line.replace('$', '@')
            line = line.replace(',', ' ')

            if line.startswith('!'):
                directive, *params = line.split()

                if directive == '!include':
                    try:
                        included_path, = params
                    except ValueError:
                        raise PolicySyntaxError(filepath, lineno,
                            'invalid number of params')
                    self.handle_include_service(service, argument,
                        pathlib.PurePosixPath(included_path),
                        filepath=filepath, lineno=lineno)
                    continue

                raise PolicySyntaxError(filepath, lineno, 'invalid directive')

            # this can raise PolicySyntaxError on its own
            self.handle_rule(self.rule_type.from_line_service(self,
                    service, argument, line, filepath=filepath, lineno=lineno),
                filepath=filepath, lineno=lineno)

        return self

    @abc.abstractmethod
    def handle_include(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno):
        '''Handle ``!include`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_include_dir(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno):
        '''Handle ``!include-dir`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_include_service(self, service, argument,
            included_path: pathlib.PurePosixPath, *, filepath, lineno):
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

    @abc.abstractmethod
    def handle_compat40(self, *, filepath, lineno):
        '''Handle ``!compat-4.0`` line when encountered in :meth:`policy_load_file`.

        This method is to be provided by subclass.
        '''
        raise NotImplementedError()

    def handle_comment(self, line, *, filepath, lineno):
        '''Handle a line with a comment

        This method may be overloaded in subclass. By default it does nothing.
        '''

class AbstractPolicy(AbstractParser):
    '''This class is a parser that accumulates the rules to form policy.'''

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        #: list of Rule objects
        self.rules = []

    def handle_rule(self, rule, *, filepath, lineno):
        # pylint: disable=unused-argument
        self.rules.append(rule)

    def evaluate(self, request):
        '''Evaluate policy

        Returns:
            AbstractResolution: For allow or ask resolutions.

        Raises:
            AccessDenied: when action should be denied unconditionally
        '''

        rule = self.find_matching_rule(request)
        return rule.action.evaluate(request)

    def find_matching_rule(self, request):
        '''Find the first rule matching given request'''

        for rule in self.rules:
            if rule.is_match(request):
                return rule
        raise AccessDenied('no matching rule found')

    def collect_targets_for_ask(self, request):
        '''Collect targets the user can choose from in 'ask' action

        Word 'targets' is used intentionally instead of 'domains', because it
        can also contains @dispvm like keywords.
        '''
        targets = set()

        # iterate over rules in reversed order to easier handle 'deny'
        # actions - simply remove matching domains from allowed set
        for rule in reversed(self.rules):
            if rule.is_match_but_target(request):
                # getattr() is for Deny, which doesn't have this attribute
                rule_target = (
                    getattr(rule.action, 'target', None) or rule.target)
                expansion = set(
                    rule_target.expand(system_info=request.system_info))

                if isinstance(rule.action, Action.deny.value):
                    targets.difference_update(expansion)
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

        # XXX remove when #951 gets fixed
        if request.source in targets:
            targets.remove(request.source)

        return targets


class AbstractFileLoader(AbstractParser):
    '''Parser that loads next files on ``!include[-service]`` directives

    This class uses regular files as accessed by :py:class:`pathlib.Path`, but
    it is possible to overload those functions and use file-like objects.
    '''

    def resolve_path(self, included_path: pathlib.PurePosixPath
            ) -> pathlib.Path:
        '''Resolve path from ``!include*`` to :py:class:`pathlib.Path`'''
        raise NotImplementedError()

    def resolve_filepath(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno) -> Tuple[TextIO, pathlib.PurePath]:
        '''Resolve ``!include[-service]`` to open file and filepath

        The callee is responsible for closing the file descriptor.

        Raises:
            qrexec.exc.PolicySyntaxError: when the path does not point to a file
        '''
        included_path = self.resolve_path(included_path)
        if not included_path.is_file():
            raise exc.PolicySyntaxError(filepath, lineno,
                'not a file: {}'.format(included_path))
        return open(str(included_path)), included_path

    def handle_include(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno):
        file, included_path = self.resolve_filepath(included_path,
            filepath=filepath, lineno=lineno)
        with file:
            self.load_policy_file(file, pathlib.PurePosixPath(included_path))

    def handle_include_service(self, service, argument,
            included_path: pathlib.PurePosixPath, *, filepath, lineno):
        service, argument = validate_service_and_argument(
            service, argument, filepath=filepath, lineno=lineno)
        file, included_path = self.resolve_filepath(included_path,
            filepath=filepath, lineno=lineno)
        with file:
            self.load_policy_file_service(
                service, argument, file, pathlib.PurePosixPath(included_path))


class AbstractDirectoryLoader(AbstractFileLoader):
    '''Parser that loads next files on ``!include-dir`` directives'''

    def resolve_dirpath(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno) -> pathlib.Path:
        '''Resolve ``!include-dir`` to directory path

        Returns:
            pathlib.Path:
        Raises:
            qrexec.exc.PolicySyntaxError: when the path does not point to
                a directory
        '''
        included_path = self.resolve_path(included_path)
        if not included_path.is_dir():
            raise exc.PolicySyntaxError(filepath, lineno,
                'not a directory: {}'.format(included_path))
        return included_path

    def handle_include_dir(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno):
        included_path = self.resolve_dirpath(included_path,
            filepath=filepath, lineno=lineno)
        self.load_policy_dir(included_path)

    def load_policy_dir(self, dirpath):
        '''Load all files in the directory (``!include-dir``)

        Args:
            dirpath (pathlib.Path): the directory to load

        Raises:
            OSError: for problems in opening files or directories
        '''
        for path in filter_filepaths(dirpath.iterdir()):
            with path.open() as file:
                self.load_policy_file(file, path)


class AbstractFileSystemLoader(AbstractDirectoryLoader, AbstractFileLoader):
    '''This class is used when policy is stored as regular files in a directory.

    Args:
        policy_path (pathlib.Path): Load this directory. Paths given to
            ``!include`` etc. directives are interpreted relative to this path.
    '''
    def __init__(self, *, policy_path=POLICYPATH, **kwds):
        super().__init__(**kwds)
        self.policy_path = pathlib.Path(policy_path)

        try:
            self.load_policy_dir(self.policy_path)
        except OSError as err:
            raise AccessDenied(
                'failed to load {} file: {!s}'.format(err.filename, err))

    def resolve_path(self, included_path):
        return (self.policy_path / included_path).resolve()

class FilePolicy(AbstractFileSystemLoader, AbstractPolicy):
    '''Full policy loaded from files.

    Usage:

    >>> policy = qrexec.policy.parser.FilePolicy()
    >>> request = Request(
    ...     'qrexec.Service', '+argument', 'source-name', 'target-name',
    ...     system_info=qrexec.utils.get_system_info())
    >>> resolution = policy.evaluate(request)
    >>> await resolution.execute('process-ident')  # asynchroneous method
    '''

    def handle_compat40(self, *, filepath, lineno):
        ''''''
        # late import for circular
        from .parser_compat import Compat40Loader

        subparser = Compat40Loader(master=self)
        subparser.execute(filepath=filepath, lineno=lineno)

class ValidateIncludesParser(AbstractParser):
    '''A parser that checks if included file does indeed exist.

    The included file is not read, because if it exists, it is assumed it
    already passed syntax check.
    '''
    def handle_include(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno):
        # TODO disallow anything other that @include:[include/]<file>
        included_path = (filepath.resolve().parent / included_path).resolve()
        if not included_path.is_file():
            raise PolicySyntaxError(filepath, lineno,
                'included path {!s} does not exist'.format(included_path))

    def handle_include_service(self, service, argument,
            included_path: pathlib.PurePosixPath, *, filepath, lineno):
        # TODO disallow anything other that @include:[include/]<file>
        included_path = (filepath.resolve().parent / included_path).resolve()
        if not included_path.is_file():
            raise PolicySyntaxError(filepath, lineno,
                'included path {!s} does not exist'.format(included_path))

    def handle_include_dir(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno):
        included_path = (filepath.resolve().parent / included_path).resolve()
        if not included_path.is_dir():
            raise PolicySyntaxError(filepath, lineno,
                'included path {!s} does not exist'.format(included_path))

    def handle_rule(self, rule, *, filepath, lineno):
        pass

class CheckIfNotIncludedParser(FilePolicy):
    '''A parser that checks if a particular file is *not* included.

    This is used while removing a particular file, to check that it is not used
    anywhere else.
    '''
    def __init__(self, *args, to_be_removed, **kwds):
        self.to_be_removed = self.policy_path / to_be_removed
        super().__init__(*args, **kwds)

    def resolve_path(self, included_path):
        included_path = super().resolve_path(included_path)
        if included_path.samefile(self.to_be_removed):
            raise ValueError(
                'included path {!s}'.format(included_path))
        return included_path

    def handle_rule(self, rule, *, filepath, lineno):
        pass

class ToposortMixIn:
    '''A helper for topological sorting the policy files'''

    @enum.unique
    class State(enum.Enum):
        '''State of topological sort algorithm'''
        ON_PATH, IN_ORDER = object(), object()

    def __init__(self, **kwds):
        self.included_paths = collections.defaultdict(set)
        super().__init__(**kwds)

        # keys and values are paths to files
        self.state = {}
        self.order = []

        self.queue = None

    def _path_to_key(self, path):
        assert isinstance(path, pathlib.PurePosixPath)
        try:
            path = path.relative_to(self.policy_path)
        except AttributeError:
            # no self.policy_path
            pass
        except ValueError:
            # not in self.policy_path
            pass
        return str(path)

    def toposort(self):
        '''Yield (file, filename) in order suitable for mass-uploading.

        A file does not include anything from any file that follows in the
        sequence.

        *file* is an open()'d file for reading.
        '''
        if not self.order:
            self.queue = set(self.included_paths.keys())
            self.queue.update(itertools.chain(self.included_paths.values()))
            while self.queue:
                self.dfs(self.queue.pop())

        for path in self.order:
            yield self.resolve_filepath(path, filepath=None, lineno=None)

    def dfs(self, node):
        '''Perform one batch of topological sort'''
        self.state[node] = self.State.ON_PATH

        for nextnode in self.included_paths[node]:
            if self.state[nextnode] == self.State.ON_PATH:
                raise ValueError('circular include; {} → {}'.format(
                    node.filepath, nextnode.filepath))
            if self.state[nextnode] == self.State.IN_ORDER:
                continue

            self.queue.discard(nextnode)
            self.dfs(nextnode)

        self.order.append(node)
        self.state[node] = self.State.IN_ORDER

    def save_included_path(self, included_path, *, filepath, lineno):
        '''Store the vertex in the dependency graph.

        Only paths inside :py:attr:`policy_path` and ``include`` directory
        (as supported by Policy API) are considered.
        '''

        key = self._path_to_key(included_path)

        if '/' in key and (
                not key.startswith('include/')
                or key.count('/') > 1):
            # TODO make this an error, since we shouldn't accept this anyway
            logging.warning('ignoring path %r included in %s on line %d; '
                'expect problems with import order',
                included_path, filepath, lineno)
            return

        self.included_paths[key].add(included_path)

    def handle_include(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno):
        # pylint: disable=missing-docstring
        logging.debug(
            'Toposorter.handle_include(included_path=%r, filepath=%r)',
            included_path, filepath)
        self.save_included_path(included_path, filepath=filepath, lineno=lineno)
        super().handle_include(included_path, filepath=filepath, lineno=lineno)

    def handle_include_service(self, service, argument,
            included_path: pathlib.PurePosixPath, *, filepath, lineno):
        # pylint: disable=missing-docstring
        logging.debug(
            'Toposorter.handle_include_service(included_path=%r, filepath=%r)',
            included_path, filepath)
        self.save_included_path(included_path, filepath=filepath, lineno=lineno)
        super().handle_include_service(service, argument, included_path,
            filepath=filepath, lineno=lineno)

    def load_policy_file(self, file, filepath):
        # pylint: disable=missing-docstring,expression-not-assigned
        # add filepath as seen
        self.included_paths[self._path_to_key(filepath)]
        super().load_policy_file(file, filepath)

class TestLoader(AbstractFileLoader):
    '''An in-memory loader used for tests

    Args:
        policy (dict or str): policy dictionary. The keys are filenames to be
            included. It should contain ``'__main__'`` key which is loaded. If
            the argument is :py:class:`str`, it behaves as it was dict's
            ``'__main__'``.
    '''
    def __init__(self, *args, policy, **kwds):
        super().__init__(*args, **kwds)
        self.policy = policy

    def resolve_filepath(self, included_path, *, filepath, lineno):
        '''
        Raises:
            qrexec.exc.PolicySyntaxError: when wrong path is included
        '''
        included_path = str(included_path)
        try:
            file = io.StringIO(self.policy[included_path])
        except KeyError:
            raise exc.PolicySyntaxError(filepath, lineno,
                'no such policy file: {!r}'.format(included_path))
        return file, pathlib.PurePosixPath(included_path + '[in-memory]')

    def handle_include_dir(self, included_path: pathlib.PurePosixPath, *,
            filepath, lineno):
        raise NotImplementedError(
            '!include-dir is unsupported in {}'.format(type(self).__name__))

class TestPolicy(ToposortMixIn, TestLoader, AbstractPolicy):
    '''Test policy, used for tests. It can be used to test most of the code
    paths used in policy parsing.

    >>> testpolicy = TestPolicy(policy={
    ...     '__main__': '!include policy2'
    ...     'policy2': '* * @anyvm @anyvm allow'})
    '''
    def __init__(self, *, policy, policy_compat=None, **kwds):
        if not isinstance(policy, collections.abc.Mapping):
            policy = {'__main__': policy}
        super().__init__(policy=policy, **kwds)
        if policy_compat is None:
            policy_compat = {}
        self.policy_compat = policy_compat
        file, filepath = self.resolve_filepath('__main__',
            filepath=None, lineno=None)
        with file:
            self.load_policy_file(file, filepath)

    def handle_compat40(self, *, filepath, lineno):
        ''''''
        # late import for circular
        from .parser_compat import TestCompat40Loader

        subparser = TestCompat40Loader(master=self, policy=self.policy_compat)
        subparser.execute(filepath=filepath, lineno=lineno)
