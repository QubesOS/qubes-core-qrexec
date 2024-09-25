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

"""Qrexec policy parser and evaluator"""

import abc
import collections
import collections.abc
import enum
import io
import itertools
import logging
import pathlib
import string

from typing import (
    Iterable,
    List,
    TextIO,
    Tuple,
    Dict,
    Optional,
    Set,
    Union,
    Type,
    NoReturn,
    FrozenSet,
    Sequence,
)

from .. import POLICYPATH, RPCNAME_ALLOWED_CHARSET, POLICYSUFFIX, RUNTIME_POLICY_PATH
from ..utils import FullSystemInfo
from .. import exc
from ..exc import (
    AccessDenied,
    PolicySyntaxError,
)

FILENAME_ALLOWED_CHARSET = set(string.digits + string.ascii_lowercase + "_.-")


def filter_filepaths(filepaths: Iterable[pathlib.Path]) -> List[pathlib.Path]:
    """Check if files should be considered by policy.

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
    """
    filepaths = [
        path
        for path in filepaths
        if path.is_file()
        and path.suffix == POLICYSUFFIX
        and not path.name.startswith(".")
    ]

    # check for invalid filenames first, then return all or nothing
    for path in filepaths:
        if not set(path.name).issubset(FILENAME_ALLOWED_CHARSET):
            raise exc.AccessDenied("invalid filename: {}".format(path))

    filepaths.sort()

    return filepaths


def parse_service_and_argument(rpcname: Union[str, pathlib.PurePath], *,
                               no_arg: str ="+") -> Tuple[str, str]:
    """Parse service and argument string.

    Parse ``SERVICE+ARGUMENT``. Argument may be empty (single ``+`` at the end)
    or omitted (no ``+`` at all). If no argument is given, `no_arg` is returned
    instead. By default this returns ``'+'``, as if argument is empty.

    A `Path` from :py:mod:`pathlib` is also accepted, in which case the filename
    is parsed.
    """
    if isinstance(rpcname, pathlib.PurePath):
        rpcname = rpcname.name

    if "+" in rpcname:
        service, argument = rpcname.split("+", 1)
        argument = "+" + argument
    else:
        service, argument = rpcname, no_arg
    return service, argument


def get_invalid_characters(s: str,
                           allowed: FrozenSet[str]=RPCNAME_ALLOWED_CHARSET,
                           disallowed: Iterable[str]="") -> Sequence[str]:
    """Return characters contained in *disallowed* and/or not int *allowed*"""
    # pylint: disable=invalid-name
    return tuple(
        sorted(set(c for c in s if c not in allowed.difference(disallowed)))
    )


def validate_service_and_argument(
    service: Optional[str],
    argument: Optional[str],
    *,
    filepath: pathlib.Path,
    lineno: Optional[int],
) -> Tuple[Optional[str], Optional[str]]:
    """Check service name and argument

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
    """

    if service == "*":
        service = None

    if service is not None:
        invalid_chars = get_invalid_characters(service, disallowed="+")
        if invalid_chars:
            raise PolicySyntaxError(
                filepath,
                lineno,
                "service {!r} contains invalid characters: {!r}".format(
                    service, invalid_chars
                ),
            )

    if argument == "*":
        argument = None

    if argument is not None:
        invalid_chars = get_invalid_characters(argument)
        if invalid_chars:
            raise PolicySyntaxError(
                filepath,
                lineno,
                "argument {!r} contains invalid characters: {!r}".format(
                    argument, invalid_chars
                ),
            )

        if not argument.startswith("+"):
            raise PolicySyntaxError(
                filepath,
                lineno,
                "argument {!r} does not start with +".format(argument),
            )

        if service is None:
            raise PolicySyntaxError(
                filepath, lineno, "only * argument allowed for * service"
            )

    return service, argument


class VMTokenMeta(abc.ABCMeta):
    # pylint: disable=missing-docstring
    exacts: collections.OrderedDict[str, Type[str]] = collections.OrderedDict()
    prefixes: collections.OrderedDict[str, Type[str]] = collections.OrderedDict()

    def __init__(cls, name: str, bases: Tuple[type], dict_: Dict[str, str]):
        super().__init__(name, bases, dict_)

        assert not ("EXACT" in dict_ and "PREFIX" in dict_)
        if "EXACT" in dict_:
            cls.exacts[dict_["EXACT"]] = cls # type: ignore
        if "PREFIX" in dict_:
            cls.prefixes[dict_["PREFIX"]] = cls # type: ignore


class VMToken(str, metaclass=VMTokenMeta):
    """A domain specification

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
    """

    def __new__(cls, token: str, *, filepath: Optional[pathlib.Path]=None,
                lineno: Optional[int]=None) -> "VMToken":
        orig_token = token

        # first, adjust some aliases
        if token == "dom0":
            # TODO: log a warning in Qubes 4.1
            token = "@adminvm"

        # if user specified just qube name, use it directly
        if not (token.startswith("@") or token == "*"):
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
                value = token[len(prefix) :]
                if not value:
                    raise PolicySyntaxError(
                        filepath,
                        lineno or 0,
                        "invalid empty {} token: {!r}".format(prefix, token),
                    )
                if value.startswith("@"):
                    # we are either part of a longer prefix (@dispvm:@tag: etc),
                    # or the token is invalid, in which case this will fallthru
                    continue
                return super().__new__(token_cls, token)

        # the loop didn't find any valid prefix, so this is not a valid token
        raise PolicySyntaxError(
            filepath,
            lineno or 0,
            "invalid {} token: {!r}".format(cls.__name__.lower(), orig_token),
        )

    value: str
    filepath: Optional[pathlib.Path]
    lineno: Optional[int]
    def __init__(self, token: str, *, filepath: Optional[pathlib.Path]=None,
                 lineno: Optional[int]=None):
        # pylint: disable=unused-argument
        super().__init__()
        self.filepath = filepath
        self.lineno = lineno
        try:
            self.value = self[len(self.PREFIX) :] # type: ignore
            assert self.value[0] != "@"
        except AttributeError:
            # self.value = self
            pass

    #   def __repr__(self):
    #       return '<{} value={!r} filepath={} lineno={}>'.format(
    #           type(self).__name__, str(self), self.filepath, self.lineno)

    # This replaces is_match() and is_match_single().
    def match(
        self,
        other: Optional[str],
        *,
        system_info: FullSystemInfo,
        source: Optional["VMToken"]=None
    ) -> bool:
        """Check if this token matches opposite token"""
        # pylint: disable=unused-argument
        return self == other

    def is_special_value(self) -> bool:
        """Check if the token specification is special (keyword) value"""
        return self.startswith("@") or self == "*"

    @property
    def type(self) -> str:
        """Type of the token

        ``'keyword'`` for special values, ``'name'`` for qube name
        """
        return "keyword" if self.is_special_value() else "name"

    @property
    def text(self) -> str:
        """Text of the token, without possibly '@' prefix"""
        return self.lstrip("@")


class Source(VMToken):
    # pylint: disable=missing-docstring
    pass


class _BaseTarget(VMToken):
    # pylint: disable=missing-docstring
    def expand(self, *, system_info: FullSystemInfo) -> Iterable[VMToken]:
        """An iterator over all valid domain names that this token would match

        This is used as part of :py:meth:`Policy.collect_targets_for_ask()`.
        """
        if self in system_info["domains"]:
            yield IntendedTarget(self)


class Target(_BaseTarget):
    # pylint: disable=missing-docstring
    pass


class Redirect(_BaseTarget):
    # pylint: disable=missing-docstring
    def __new__(
        cls,
        value: Optional[str],
        *,
        filepath: Optional[pathlib.Path]=None,
        lineno: Optional[int]=None,
    ) -> "Redirect":
        if value is None:
            return None # type: ignore
        return super().__new__(cls, value, filepath=filepath, lineno=lineno) # type: ignore


# this method (with overloads in subclasses) was verify_target_value
class IntendedTarget(VMToken):
    # pylint: disable=missing-docstring
    def verify(self, *, system_info: FullSystemInfo) -> VMToken:
        """Check if given value names valid target

        This function check if given value is not only syntactically correct,
        but also if names valid service call target (existing domain, or valid
        ``'@dispvm'`` like keyword). If the domain does not exist,
        returns a DefaultVM.

        Args:
            system_info: information about the system

        Returns:
            VMToken: for successful verification

        Raises:
            qrexec.exc.AccessDenied: for failed verification
        """
        # for subclass it has to be overloaded
        # pylint: disable=unidiomatic-typecheck
        if type(self) != IntendedTarget:
            raise NotImplementedError()

        if self not in system_info["domains"]:
            logging.warning(
                "qrexec: target %r does not exist, using @default instead",
                str(self),
            )
            return DefaultVM(
                "@default", filepath=self.filepath, lineno=self.lineno
            )

        return self


# And the tokens. Inheritance defines, where the token can be used.


class WildcardVM(Source, Target):
    # any, including AdminVM

    # pylint: disable=missing-docstring,unused-argument
    EXACT = "*"

    def match(
        self,
        other: Optional[str],
        *,
        system_info: FullSystemInfo,
        source: Optional[VMToken]=None
    ) -> bool:
        return True

    def expand(self, *, system_info: FullSystemInfo) -> Iterable[VMToken]:
        for name, domain in system_info["domains"].items():
            yield IntendedTarget(name)
            if domain["template_for_dispvms"]:
                yield DispVMTemplate("@dispvm:" + name)
        yield DispVM("@dispvm")


class AdminVM(Source, Target, Redirect, IntendedTarget):
    # no Source, for calls originating from AdminVM policy is not evaluated
    # pylint: disable=missing-docstring,unused-argument
    EXACT = "@adminvm"

    def expand(self, *, system_info: FullSystemInfo) -> Iterable["AdminVM"]:
        yield self

    def verify(self, *, system_info: FullSystemInfo) -> "AdminVM":
        return self


class AnyVM(Source, Target):
    # pylint: disable=missing-docstring,unused-argument
    EXACT = "@anyvm"

    def match(
        self,
        other: Optional[str],
        *,
        system_info: FullSystemInfo,
        source: Optional[VMToken]=None
    ) -> bool:
        return other != "@adminvm"

    def expand(self, *, system_info: FullSystemInfo) -> Iterable[VMToken]:
        for name, domain in system_info["domains"].items():
            if domain["type"] != "AdminVM":
                yield IntendedTarget(name)
            if domain["template_for_dispvms"]:
                yield DispVMTemplate("@dispvm:" + name)
        yield DispVM("@dispvm")


class DefaultVM(Target, IntendedTarget):
    # pylint: disable=missing-docstring,unused-argument
    EXACT = "@default"

    def expand(self, *, system_info: FullSystemInfo) -> Iterable[NoReturn]:
        yield from ()

    def verify(self, *, system_info: FullSystemInfo) -> "DefaultVM":
        return self


class TypeVM(Source, Target):
    # pylint: disable=missing-docstring,unused-argument
    PREFIX = "@type:"

    def match(
        self,
        other: Optional[str],
        *,
        system_info: FullSystemInfo,
        source: Optional[VMToken]=None
    ) -> bool:
        _system_info = system_info["domains"]
        return (
            other in _system_info
            and self.value == _system_info[other]["type"]
        )

    def expand(self, *, system_info: FullSystemInfo) -> Iterable[IntendedTarget]:
        for name, domain in system_info["domains"].items():
            if domain["type"] == self.value:
                yield IntendedTarget(name)


class TagVM(Source, Target):
    # pylint: disable=missing-docstring,unused-argument
    PREFIX = "@tag:"

    def match(
        self,
        other: Optional[str],
        *,
        system_info: FullSystemInfo,
        source: Optional[VMToken]=None
    ) -> bool:
        _system_info = system_info["domains"]
        return (
            other in _system_info
            and self.value in _system_info[other]["tags"]
        )

    def expand(self, *, system_info: FullSystemInfo) -> Iterable[IntendedTarget]:
        for name, domain in system_info["domains"].items():
            if self.value in domain["tags"]:
                yield IntendedTarget(name)


class DispVM(Target, Redirect, IntendedTarget):
    # pylint: disable=missing-docstring,unused-argument
    EXACT = "@dispvm"

    def match(
        self,
        other: Optional[str],
        *,
        system_info: FullSystemInfo,
        source: Optional[VMToken]=None
    ) -> bool:
        return self == other

    def expand(self, *, system_info: FullSystemInfo) -> Iterable["DispVM"]:
        yield self

    def verify(self, *, system_info: FullSystemInfo) -> "DispVM":
        return self

    @staticmethod
    def get_dispvm_template(
        source: str,
        *,
        system_info: FullSystemInfo,
    ) -> Optional["DispVMTemplate"]:
        """Given source, get appropriate template for DispVM. Maybe None."""
        _system_info = system_info["domains"]
        if source not in _system_info:
            return None
        template = _system_info[source].get("default_dispvm", None)
        if template is None:
            return None
        return DispVMTemplate("@dispvm:" + template)

class DispVMTemplate(Source, Target, Redirect, IntendedTarget):
    # pylint: disable=missing-docstring,unused-argument
    PREFIX = "@dispvm:"

    def match(
        self,
        other: Optional[str],
        *,
        system_info: FullSystemInfo,
        source: Optional[VMToken]=None
    ) -> bool:
        if isinstance(other, DispVM) and source is not None:
            return self == other.get_dispvm_template(
                source, system_info=system_info
            )
        return self == other

    def expand(self, *, system_info: FullSystemInfo) -> Iterable["DispVMTemplate"]:
        if system_info["domains"][self.value]["template_for_dispvms"]:
            yield self
        # else: log a warning?

    def verify(self, *, system_info: FullSystemInfo) -> "DispVMTemplate":
        _system_info = system_info["domains"]
        if (
            self.value not in _system_info
            or not _system_info[self.value]["template_for_dispvms"]
        ):
            raise AccessDenied(
                "not a template for dispvm: {}".format(self.value)
            )
        return self


class DispVMTag(Source, Target):
    # pylint: disable=missing-docstring,unused-argument
    PREFIX = "@dispvm:@tag:"

    def match(
        self,
        other: Optional[str],
        *,
        system_info: FullSystemInfo,
        source: Optional[VMToken]=None
    ) -> bool:
        if isinstance(other, DispVM):
            assert source is not None
            other = other.get_dispvm_template(source, system_info=system_info)

        if not isinstance(other, DispVMTemplate):
            # 1) original other may have been neither @dispvm:<name> nor @dispvm
            # 2) other.get_dispvm_template() may have been None
            return False

        domain = system_info["domains"][other.value]
        if not domain["template_for_dispvms"]:
            return False
        if not self.value in domain["tags"]:
            return False

        return True

    def expand(self, *, system_info: FullSystemInfo) -> Iterable[VMToken]:
        for name, domain in system_info["domains"].items():
            if self.value in domain["tags"] and domain["template_for_dispvms"]:
                yield DispVMTemplate("@dispvm:" + name)


#
# resolutions
#


class AbstractResolution(metaclass=abc.ABCMeta):
    """Object representing positive policy evaluation result -
    either ask or allow action"""

    notify: bool
    def __init__(self, rule: "Rule", request: "Request", *, user: Optional[str]):

        #: policy rule from which this action is derived
        self.rule = rule
        #: request
        self.request = request
        #: the user to run command as, or None for default
        self.user = user
        #: whether to notify the user about the action taken
        self.notify = rule.action.notify

    @abc.abstractmethod
    async def execute(self) -> str:
        """
        Execute the action. For allow, this runs the qrexec. For ask, it asks
        user and then (depending on verdict) runs the call.

        Args:
            caller_ident (str): Service caller ident
                (``process_ident,source_name, source_id``)
        """
        raise NotImplementedError()


class AllowResolution(AbstractResolution):
    """Resolution returned for :py:class:`Rule` with :py:class:`Allow`."""

    def __init__(
        self,
        rule: "Rule",
        request: "Request",
        *,
        user: Optional[str],
        target: str,
        autostart: bool,
    ):
        super().__init__(rule, request, user=user)
        #: target domain the service should be connected to
        self.target = target
        self.autostart = autostart
        assert isinstance(self.autostart,bool)

    @classmethod
    def from_ask_resolution(
        cls,
        ask_resolution: "AskResolution",
        *,
        target: str
    ) -> "AllowResolution":
        """This happens after user manually approved the call"""
        if target.startswith("@dispvm:"):
            target = DispVMTemplate(target)
        return cls(
            ask_resolution.rule,
            ask_resolution.request,
            user=ask_resolution.user,
            target=target,
            autostart=ask_resolution.autostart,
        )

    async def execute(self) -> str:
        """Return the allowed action"""
        request, target = self.request, self.target
        assert target is not None
        assert isinstance(self.autostart,bool)

        # XXX remove when #951 gets fixed
        if request.source == target:
            raise AccessDenied("loopback qrexec connection not supported")

        return f"""\
user={self.user or 'DEFAULT'}
result=allow
target={self.target}
autostart={self.autostart}
requested_target={self.request.target}"""

class AskResolution(AbstractResolution):
    """Resolution returned for :py:class:`Rule` with :py:class:`Ask`.

    This base class is a dummy implementation which behaves as if user always
    denied the call. The programmer is expected to inherit from this class and
    overload :py:meth:`execute` to display the question to the user by
    appropriate means. User should have choice among :py:attr:`targets_for_ask`.
    If :py:attr:`default_target` is not :py:obj:`None`, that should be the
    default. Otherwise there should be no default. After querying the user,
    :py:meth:`handle_user_response` should be called. For negative answers,
    raising :py:class:`qrexec.exc.AccessDenied` is also enough.

    The child class should be supplied as part of :py:class:`Request`.
    """
    # pylint: disable=too-many-arguments
    def __init__(self,
                 rule: "Rule",
                 request: "Request",
                 *,
                 # targets for the user to choose from
                 targets_for_ask: Sequence[str],
                 # default target, or None
                 default_target: Optional[str],
                 autostart: bool,
                 user: Optional[str]):
        super().__init__(rule, request, user=user)
        assert default_target is None or default_target in targets_for_ask
        self.targets_for_ask = targets_for_ask
        self.default_target = default_target
        self.autostart = autostart

    def handle_user_response(self, response: bool, target: str) -> AllowResolution:
        """
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
        """
        # pylint: disable=redefined-variable-type
        if not response:
            raise AccessDenied(
                "denied by the user {}:{}".format(
                    self.rule.filepath, self.rule.lineno
                ),
                notify=self.notify,
            )

        if target not in self.targets_for_ask:
            raise AccessDenied("target {} is not a valid choice".format(target))

        return self.request.allow_resolution_type.from_ask_resolution(
            self, target=target
        )

    def handle_invalid_response(self) -> NoReturn:
        """
        Handle invalid response for the 'ask' action. Throws AccessDenied.
        """
        # pylint: disable=no-self-use
        raise AccessDenied("invalid response")

    async def execute(self) -> NoReturn:
        """Ask the user for permission.

        This method should be overloaded in children classes. This
        implementation always denies the request.

        Raises:
            qrexec.exc.AccessDenied: always
        """
        raise AccessDenied("denied for non-interactive ask")


#
# request
#
# pylint: disable=too-many-instance-attributes
class Request:
    """Qrexec request

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
    """

    def __init__(
        self,
        service: Optional[str],
        argument: str,
        source: str,
        target: str,
        *,
        system_info: FullSystemInfo,
        allow_resolution_type: Type[AllowResolution]=AllowResolution,
        ask_resolution_type: Type[AskResolution]=AskResolution
    ):

        if target == "":
            target = "@default"
        assert argument and argument[0] == "+"

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
    """Base class for actions

    Children of this class are types of objects representing action in policy
    rule (:py:attr:`Rule.action`). Not to be confused with
    :py:class:`AbstractResolution`, which happens when particular rule is
    matched to a :py:class:`Request`.

    Keyword arguments to __init__ are taken from parsing params in the rule, so
    this defines, what params are valid for which action.
    """

    target: Optional[_BaseTarget]
    def __init__(self, rule: "Rule"):
        #: the rule that holds this action
        self.rule = rule
        self.target = None

    @abc.abstractmethod
    def evaluate(self, request: Request) -> AbstractResolution:
        """Evaluate the request.

        Depending on action and possibly user's decision either return
        a resolution or raise exception.

        Args:
            request (Request): the request that was matched to the rule

        Returns:
            AbstractResolution: for successful requests

        Raises:
            qrexec.exc.AccessDenied: for denied requests
        """
        raise NotImplementedError()

    def actual_target(self, intended_target: VMToken) -> IntendedTarget:
        """If action has redirect, it is it. Otherwise, the rule's own target

        Args:
            intended_target (IntendedTarget): :py:attr:`Request.target`

        Returns:
            IntendedTarget: either :py:attr:`target`, if not None, or
                *intended_target*
        """
        return IntendedTarget(self.target or intended_target)

    @staticmethod
    def allow_no_autostart(target: str, system_info: FullSystemInfo) -> bool:
        """
        Should we allow this target when autostart is disabled
        """
        if target == "@adminvm":
            return True
        if target.startswith("@dispvm"):
            return False
        try:
            return system_info["domains"][target]["power_state"] == "Running"
        except KeyError as e:
            raise AssertionError from e


class Deny(ActionType):
    # pylint: disable=missing-docstring
    def __init__(self, rule: "Rule", *, notify: Optional[bool]=None):
        super().__init__(rule)
        self.notify = True if notify is None else notify

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>"

    def __str__(self) -> str:
        return "deny"

    def evaluate(self, request: Request) -> NoReturn:
        """
        Raises:
            qrexec.exc.AccessDenied:
        """
        raise AccessDenied(
            "denied by policy {}:{}".format(
                self.rule.filepath, self.rule.lineno
            ),
            notify=self.notify,
        )

    def actual_target(self, intended_target: object) -> NoReturn:
        """"""  # not documented in HTML
        # pylint: disable=empty-docstring
        raise AccessDenied("programmer error")


class Allow(ActionType):
    # pylint: disable=missing-docstring
    autostart: bool
    notify: bool
    user: Optional[str]
    target: Redirect
    def __init__(
        self,
        rule: "Rule",
        *,
        target: Optional[str]=None,
        user: Optional[str] = None,
        notify: bool = False,
        autostart: bool = True,
    ): # pylint: disable=too-many-arguments
        super().__init__(rule)
        self.target = Redirect(
            target, filepath=self.rule.filepath, lineno=self.rule.lineno
        )
        self.user = user
        self.notify = notify
        self.autostart = autostart

    def __repr__(self) -> str:
        return "<{} target={!r} user={!r}>".format(
            type(self).__name__, self.target, self.user
        )

    def __str__(self) -> str:
        return_str = "allow"
        if self.target:
            return_str += f" target={self.target}"
        if self.user:
            return_str += f" user={self.user}"
        return return_str

    def evaluate(self, request: Request) -> AllowResolution:
        """
        Returns:
            AllowResolution: for successful requests

        Raises:
            qrexec.exc.AccessDenied: for invalid requests
        """
        assert self.rule.is_match(request)

        target: str = self.actual_target(request.target).verify(
            system_info=request.system_info
        )
        if target == "@default":
            raise AccessDenied(
                "policy define 'allow' action at {}:{} but no target is "
                "specified by caller or policy".format(
                    self.rule.filepath, self.rule.lineno
                )
            )
        if isinstance(target, DispVM):
            target_ = target.get_dispvm_template( # pylint: disable=no-member
                request.source, system_info=request.system_info
            )
            if target_ is None:
                raise AccessDenied(
                    "policy define 'allow' action to @dispvm at {}:{} "
                    "but no DispVM base is set for this VM".format(
                        self.rule.filepath, self.rule.lineno
                    )
                )
            target = target_
            del target_
        # expand default AdminVM
        elif target == "@adminvm":
            target = "dom0"

        if not self.autostart and not self.allow_no_autostart(
            target, request.system_info
        ):
            raise AccessDenied(
                "target {} is denied because it would require autostart".format(
                    target
                ),
                notify=self.notify,
            )

        return request.allow_resolution_type(
            self.rule, request, user=self.user, target=target, autostart=self.autostart
        )


class Ask(ActionType):
    # pylint: disable=missing-docstring,too-many-arguments
    def __init__(
        self,
        rule: "Rule",
        *,
        target: Optional[str]=None,
        default_target: Optional[str]=None,
        user: Optional[str] = None,
        notify: bool = False,
        autostart: bool = True,
    ):
        super().__init__(rule)
        self.target = Redirect(
            target, filepath=self.rule.filepath, lineno=self.rule.lineno
        )
        self.default_target = Redirect(
            default_target, filepath=self.rule.filepath, lineno=self.rule.lineno
        )
        self.user = user
        self.notify = False if notify is None else notify
        self.autostart = True if autostart is None else autostart

    def __repr__(self) -> str:
        return "<{} target={!r} default_target={!r} user={!r}>".format(
            type(self).__name__, self.target, self.default_target, self.user
        )

    def __str__(self) -> str:
        return_str = "ask"
        if self.target:
            return_str += f" target={self.target}"
        if self.default_target:
            return_str += f" default_target={self.default_target}"
        if self.user:
            return_str += f" user={self.user}"
        return return_str

    def evaluate(self, request: Request) -> AskResolution:
        """
        Returns:
            AskResolution

        Raises:
            qrexec.exc.AccessDenied: for invalid requests
        """
        assert self.rule.is_match(request)

        targets_for_ask: Iterable[str]
        if self.target is not None:
            targets_for_ask = [self.target]
        else:
            targets_for_ask = list(
                self.rule.policy.collect_targets_for_ask(request)
            )

        if not self.autostart:
            targets_for_ask = [
                target
                for target in targets_for_ask
                if self.allow_no_autostart(target, request.system_info)
            ]

        if not targets_for_ask:
            raise AccessDenied(
                "policy define 'ask' action at {}:{} but no target is "
                "available to choose from".format(
                    self.rule.filepath, self.rule.lineno
                )
            )

        default_target: Optional[str] = self.default_target
        if default_target is not None:
            # expand default DispVM
            if isinstance(default_target, DispVM):
                # pylint is confused by the metaclass - default_target is
                # constructed as Redirect(), but in fact it can be any subclass
                # pylint: disable=no-member
                default_target = default_target.get_dispvm_template(
                    request.source, system_info=request.system_info
                )
            # expand default AdminVM
            elif isinstance(default_target, AdminVM):
                default_target = "dom0"

        return request.ask_resolution_type(
            self.rule,
            request,
            user=self.user,
            targets_for_ask=targets_for_ask,
            default_target=default_target,
            autostart=self.autostart,
        )


@enum.unique
class Action(enum.Enum):
    """Action as defined by policy"""

    # pylint: disable=invalid-name
    allow = Allow
    deny = Deny
    ask = Ask


class Rule:
    """A single line of policy file

    Avoid instantiating manually, use either :py:meth:`from_line()` or
    :py:meth:`from_line_service()`.
    """

    # pylint: disable=too-many-instance-attributes,too-many-positional-arguments

    action: Union[Allow, Deny, Ask]
    def __init__(
        self,
        service: str,
        argument: str,
        source: str,
        target: str,
        action: str,
        params: List[str],
        *,
        policy: "AbstractPolicy",
        filepath: pathlib.Path,
        lineno: Optional[int],
    ):
        # pylint: disable=too-many-arguments

        #: the parser that this rule belongs to
        self.policy = policy
        #: the file path
        self.filepath = filepath
        #: the line number
        self.lineno = lineno

        service_, argument_ = validate_service_and_argument(
            service, argument, filepath=filepath, lineno=lineno
        )

        #: the qrexec service
        self.service = service_
        #: the argument to the service
        self.argument = argument_
        #: source specification
        self.source = Source(source, filepath=filepath, lineno=lineno)
        #: target specification
        self.target = Target(target, filepath=filepath, lineno=lineno)

        try:
            actiontype = Action[action].value
        except KeyError as err:
            raise PolicySyntaxError(
                filepath, lineno, "invalid action: {}".format(action)
            ) from err

        kwds: Dict[str, Union[str, bool]] = {}
        for param in params:
            try:
                key, value = param.split("=", maxsplit=1)
            except ValueError as err:
                raise PolicySyntaxError(
                    filepath,
                    lineno,
                    "invalid action parameter syntax: {!r}".format(param),
                ) from err
            if key in kwds:
                raise PolicySyntaxError(
                    filepath, lineno, "parameter given twice: {!r}".format(key)
                )
            kwds[key] = value

        # boolean parameters
        for key in ["notify", "autostart"]:
            if key in kwds:
                if kwds[key] not in ["yes", "no"]:
                    raise PolicySyntaxError(
                        filepath,
                        lineno,
                        "{!r} is {!r}, but can be only 'yes' or 'no'".format(
                            key, kwds[key]
                        ),
                    )
                kwds[key] = kwds[key] == "yes"

        try:
            #: policy action
            self.action = actiontype(rule=self, **kwds)
        except TypeError as err:
            raise PolicySyntaxError(
                filepath,
                lineno,
                "invalid parameters for action {}: {}".format(
                    actiontype.__name__, params
                ),
            ) from err

        # verify special cases
        if (
            isinstance(self.target, DefaultVM)
            and isinstance(self.action, Allow)
            and self.action.target is None
        ):
            raise PolicySyntaxError(
                filepath,
                lineno,
                "allow action for @default rule must specify target= option",
            )

    def __repr__(self) -> str:
        return (
            "<{} service={!r} argument={!r}"
            " source={!r} target={!r} action={!r}>".format(
                type(self).__name__,
                self.service,
                self.argument,
                self.source,
                self.target,
                self.action,
            )
        )

    def __str__(self) -> str:
        return_str = f"{self.service}\t"
        if self.argument:
            return_str += f'{self.argument}\t'
        else:
            return_str += '*\t'
        return_str += f'{self.source}\t{self.target}\t{str(self.action)}'
        return return_str

    @classmethod
    def from_line(cls, policy, line, *, filepath, lineno):
        """
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
        """

        try:
            service, argument, source, target, action, *params = line.split()
        except ValueError as err:
            raise PolicySyntaxError(
                filepath, lineno, "wrong number of fields"
            ) from err

        return cls(
            service,
            argument,
            source,
            target,
            action,
            params,
            policy=policy,
            filepath=filepath,
            lineno=lineno,
        )

    @classmethod
    def from_line_service(
        cls, policy, service, argument, line, *, filepath, lineno
    ):
        """Load a single line in old format.

        Args:
            service: the service for which this line applies
            argument: argument for the service
            line (str): the line to be parsed
            filepath (pathlib.Path): the file from which this line was taken
            lineno (int): the line number

        Raises:
            PolicySyntaxError: when syntax error is found
        """
        try:
            source, target, *action_and_params = line.split()
        except ValueError as err:
            raise PolicySyntaxError(
                filepath, lineno, "wrong number of fields"
            ) from err

        action_and_params = tuple(
            itertools.chain(*(p.split(",") for p in action_and_params))
        )

        try:
            action, *params = action_and_params
        except ValueError as err:
            raise PolicySyntaxError(
                filepath, lineno, "wrong number of fields"
            ) from err

        return cls(
            service,
            argument,
            source,
            target,
            action,
            params,
            policy=policy,
            filepath=filepath,
            lineno=lineno,
        )

    def is_match(self, request: Request) -> bool:
        """Check if given request matches this line.

        :param request: request to check against
        :return: True or False
        """

        return self.is_match_but_target(request) and self.target.match(
            request.target,
            source=request.source,
            system_info=request.system_info,
        )

    def is_match_but_target(self, request: Request) -> bool:
        """Check if given (service, argument source) matches this line.

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
        """

        return (
            (self.service is None or self.service == request.service)
            and (self.argument is None or self.argument == request.argument)
            and self.source.match(
                request.source, system_info=request.system_info
            )
        )


class AbstractParser(metaclass=abc.ABCMeta):
    """A minimal, pluggable, validating policy parser"""

    #: default rule type
    rule_type = Rule

    @staticmethod
    def _fix_filepath(file, filepath):
        if filepath and not isinstance(filepath, pathlib.Path):
            filepath = pathlib.Path(filepath)
        if filepath is None:
            try:
                filepath = pathlib.Path(file.name)
            except AttributeError:
                if isinstance(file, io.IOBase):
                    filepath = "<buffer>"
        return file, filepath

    def load_policy_file(self, file, filepath):
        """Parse a policy file"""
        file, filepath = self._fix_filepath(file, filepath)

        for lineno, line in enumerate(file, start=1):
            line = line.strip()

            # skip empty lines and comments
            if not line or line[0] == "#":
                self.handle_comment(line, filepath=filepath, lineno=lineno)
                continue

            if line.startswith("!"):
                directive, *params = line.split()

                if directive == "!include":
                    try:
                        (included_path,) = params
                    except ValueError as err:
                        raise PolicySyntaxError(
                            filepath, lineno, "invalid number of params"
                        ) from err
                    self.handle_include(
                        pathlib.PurePosixPath(included_path),
                        filepath=filepath,
                        lineno=lineno,
                    )
                    continue
                if directive == "!include-dir":
                    try:
                        (included_path,) = params
                    except ValueError as err:
                        raise PolicySyntaxError(
                            filepath, lineno, "invalid number of params"
                        ) from err
                    self.handle_include_dir(
                        pathlib.PurePosixPath(included_path),
                        filepath=filepath,
                        lineno=lineno,
                    )
                    continue
                if directive == "!include-service":
                    try:
                        service, argument, included_path = params
                    except ValueError as err:
                        raise PolicySyntaxError(
                            filepath, lineno, "invalid number of params"
                        ) from err
                    self.handle_include_service(
                        service,
                        argument,
                        pathlib.PurePosixPath(included_path),
                        filepath=filepath,
                        lineno=lineno,
                    )
                    continue

                if directive == "!compat-4.0":
                    if params:
                        raise PolicySyntaxError(
                            filepath, lineno, "invalid number of params"
                        )
                    logging.warning(
                        "warning: !compat-4.0 directive in file %s line %s"
                        " is transitional and will be deprecated",
                        filepath,
                        lineno,
                    )
                    self.handle_compat40(filepath=filepath, lineno=lineno)
                    continue

                raise PolicySyntaxError(filepath, lineno, "invalid directive")

            # this can raise PolicySyntaxError on its own
            self.handle_rule(
                self.rule_type.from_line(
                    self, line, filepath=filepath, lineno=lineno
                ),
                filepath=filepath,
                lineno=lineno,
            )

        return self

    def load_policy_file_service(self, service, argument, file, filepath):
        """Parse a policy file from ``!include-service``"""
        file, filepath = self._fix_filepath(file, filepath)

        for lineno, line in enumerate(file, start=1):
            line = line.strip()

            # skip empty lines and comments
            if not line or line[0] == "#":
                continue

            # compatibility substitutions, some may be unspecified and may be
            # removed in a future version
            line = line.replace("$include:", "!include ")
            line = line.replace("$", "@")
            line = line.replace(",", " ")

            if line.startswith("!"):
                directive, *params = line.split()

                if directive == "!include":
                    try:
                        (included_path,) = params
                    except ValueError as err:
                        raise PolicySyntaxError(
                            filepath, lineno, "invalid number of params"
                        ) from err
                    self.handle_include_service(
                        service,
                        argument,
                        pathlib.PurePosixPath(included_path),
                        filepath=filepath,
                        lineno=lineno,
                    )
                    continue

                raise PolicySyntaxError(filepath, lineno, "invalid directive")

            # this can raise PolicySyntaxError on its own
            self.handle_rule(
                self.rule_type.from_line_service(
                    self,
                    service,
                    argument,
                    line,
                    filepath=filepath,
                    lineno=lineno,
                ),
                filepath=filepath,
                lineno=lineno,
            )

        return self

    @abc.abstractmethod
    def handle_include(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ):
        """Handle ``!include`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_include_dir(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ):
        """Handle ``!include-dir`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_include_service(
        self,
        service,
        argument,
        included_path: pathlib.PurePosixPath,
        *,
        filepath,
        lineno
    ):
        """Handle ``!include-service`` line when encountered in
        :meth:`policy_load_file`.

        This method is to be provided by subclass.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_rule(self, rule, *, filepath, lineno):
        """Handle a line with a rule.

        This method is to be provided by subclass.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_compat40(self, *, filepath, lineno):
        """Handle ``!compat-4.0`` line when encountered in :meth:`policy_load_file`.

        This method is to be provided by subclass.
        """
        raise NotImplementedError()

    def handle_comment(self, line, *, filepath, lineno):
        """Handle a line with a comment

        This method may be overloaded in subclass. By default, it does nothing.
        """


class AbstractPolicy(AbstractParser):
    """This class is a parser that accumulates the rules to form policy."""

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        #: list of Rule objects
        self.rules: List[Rule] = []

    def handle_rule(self, rule, *, filepath, lineno):
        # pylint: disable=unused-argument
        self.rules.append(rule)

    def evaluate(self, request):
        """Evaluate policy

        Returns:
            AbstractResolution: For allow or ask resolutions.

        Raises:
            AccessDenied: when action should be denied unconditionally
        """

        rule = self.find_matching_rule(request)
        return rule.action.evaluate(request)

    def find_matching_rule(self, request):
        """Find the first rule matching given request"""

        for rule in self.rules:
            if rule.is_match(request):
                return rule
        raise AccessDenied("no matching rule found")

    def find_rules_for_service(self, service):
        for rule in self.rules:
            if rule.service is None or rule.service == service:
                yield rule

    def collect_targets_for_ask(self, request):
        """Collect targets the user can choose from in 'ask' action

        Word 'targets' is used intentionally instead of 'domains', because it
        can also contains @dispvm like keywords.
        """
        targets: Set[str] = set()

        # iterate over rules in reversed order to easier handle 'deny'
        # actions - simply remove matching domains from allowed set
        for rule in reversed(self.rules):
            if rule.is_match_but_target(request):
                # getattr() is for Deny, which doesn't have this attribute
                rule_target = (
                    getattr(rule.action, "target", None) or rule.target
                )
                expansion = set(
                    rule_target.expand(system_info=request.system_info)
                )

                if isinstance(rule.action, Action.deny.value):
                    targets.difference_update(expansion)
                else:
                    targets.update(expansion)

        # expand default DispVM
        if "@dispvm" in targets:
            targets.remove("@dispvm")
            dispvm = DispVM("@dispvm").get_dispvm_template(
                request.source, system_info=request.system_info
            )
            if dispvm is not None:
                targets.add(dispvm)

        # expand other keywords
        if "@adminvm" in targets:
            targets.remove("@adminvm")
            targets.add("dom0")

        # XXX remove when #951 gets fixed
        if request.source in targets:
            targets.remove(request.source)

        return targets


class AbstractFileLoader(AbstractParser):
    """Parser that loads next files on ``!include[-service]`` directives

    This class uses regular files as accessed by :py:class:`pathlib.Path`, but
    it is possible to overload those functions and use file-like objects.
    """

    def resolve_path(
        self, included_path: pathlib.PurePosixPath
    ) -> pathlib.Path:
        """Resolve path from ``!include*`` to :py:class:`pathlib.Path`"""
        raise NotImplementedError()

    def resolve_filepath(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ) -> Tuple[TextIO, pathlib.PurePath]:
        """Resolve ``!include[-service]`` to open file and filepath

        The callee is responsible for closing the file descriptor.

        Raises:
            qrexec.exc.PolicySyntaxError: when the path does not point to a file
        """
        resolved_included_path: pathlib.Path = self.resolve_path(included_path)
        if not resolved_included_path.is_file():
            raise exc.PolicySyntaxError(
                filepath, lineno, "not a file: {}".format(resolved_included_path)
            )
        # pylint: disable=consider-using-with
        return (open(str(resolved_included_path), encoding='utf-8'),
                pathlib.PurePath(resolved_included_path))

    def handle_include(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ):
        file, resolved_included_path = self.resolve_filepath(
            included_path, filepath=filepath, lineno=lineno
        )
        with file:
            self.load_policy_file(file, resolved_included_path)

    def handle_include_service(
        self,
        service,
        argument,
        included_path: pathlib.PurePosixPath,
        *,
        filepath,
        lineno
    ):
        service, argument = validate_service_and_argument(
            service, argument, filepath=filepath, lineno=lineno
        )
        file, resolved_included_path = self.resolve_filepath(
            included_path, filepath=filepath, lineno=lineno
        )
        with file:
            self.load_policy_file_service(
                service, argument, file, resolved_included_path
            )


class AbstractDirectoryLoader(AbstractFileLoader):
    """Parser that loads next files on ``!include-dir`` directives"""

    def resolve_dirpath(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ) -> pathlib.Path:
        """Resolve ``!include-dir`` to directory path

        Returns:
            pathlib.Path:
        Raises:
            qrexec.exc.PolicySyntaxError: when the path does not point to
                a directory
        """
        resolved_included_path = self.resolve_path(included_path)
        if not resolved_included_path.is_dir():
            raise exc.PolicySyntaxError(
                filepath, lineno, "not a directory: {}".format(resolved_included_path)
            )
        return resolved_included_path

    def handle_include_dir(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ):
        resolved_included_path = self.resolve_dirpath(
            included_path, filepath=filepath, lineno=lineno
        )
        self.load_policy_dir(resolved_included_path)

    def load_policy_dir(self, dirpath):
        """Load all files in the directory (``!include-dir``)

        Args:
            dirpath (pathlib.Path): the directory to load

        Raises:
            OSError: for problems in opening files or directories
        """
        for path in filter_filepaths(dirpath.iterdir()):
            with path.open() as file:
                self.load_policy_file(file, path)


class AbstractFileSystemLoader(AbstractDirectoryLoader, AbstractFileLoader):
    """This class is used when policy is stored as regular files in a directory.

    Args:
        policy_path: Load these directories. Paths given to
            ``!include`` etc. directives in a file are interpreted relative to
            the path from which the file was loaded.
    """

    policy_path: Optional[pathlib.Path]
    def __init__(
        self,
        *,
        policy_path: Union[None, pathlib.PurePath, Iterable[pathlib.PurePath]]
    ) -> None:
        super().__init__()
        if policy_path is None:
            iterable_policy_paths = [RUNTIME_POLICY_PATH, POLICYPATH]
        elif isinstance(policy_path, pathlib.Path):
            iterable_policy_paths = [policy_path]
        elif isinstance(policy_path, list):
            iterable_policy_paths = policy_path
        else:
            raise TypeError("unexpected type of policy path in AbstractFileSystemLoader.__init__!")
        try:
            self.load_policy_dirs(iterable_policy_paths)
        except OSError as err:
            raise AccessDenied(
                "failed to load {} file: {!s}".format(err.filename, err)
            ) from err
        self.policy_path = None

    def load_policy_dirs(self, paths: Iterable[pathlib.PurePath]) -> None:
        already_seen = set()
        final_list = []
        for path in paths:
            for file_path in filter_filepaths(pathlib.Path(path).iterdir()):
                basename = file_path.name
                if basename not in already_seen:
                    already_seen.add(basename)
                    final_list.append(file_path)
        final_list.sort(key=lambda x: x.name)
        for file_path in final_list:
            with file_path.open() as file:
                self.policy_path = file_path.parent
                try:
                    self.load_policy_file(file, file_path)
                finally:
                    self.policy_path = None

    def resolve_path(self, included_path: pathlib.PurePosixPath) -> pathlib.Path:
        assert self.policy_path is not None, "Tried to resolve a path when not loading policy"
        return (self.policy_path / included_path).resolve()


class FilePolicy(AbstractFileSystemLoader, AbstractPolicy):
    """Full policy loaded from files.

    Usage:

    >>> policy = qrexec.policy.parser.FilePolicy()
    >>> request = Request(
    ...     'qrexec.Service', '+argument', 'source-name', 'target-name',
    ...     system_info=qrexec.utils.get_system_info())
    >>> resolution = policy.evaluate(request)
    >>> await resolution.execute('process-ident')  # asynchroneous method
    """

    def handle_compat40(self, *, filepath, lineno):
        """"""
        # late import for circular
        from .parser_compat import Compat40Loader

        subparser = Compat40Loader(master=self)
        subparser.execute(filepath=filepath, lineno=lineno)


class ValidateParser(FilePolicy):
    """
    A parser that validates the policy directory along with proposed changes.

    Pass files to be overriden in the ``overrides`` dictionary, with either
    new content, or None if the file is to be deleted.
    """

    def __init__(
        self,
        *,
        overrides: Dict[pathlib.Path, Optional[str]],
        policy_path: Union[None, pathlib.PurePath, Iterable[pathlib.PurePath]] = None,
    ) -> None:
        self.overrides = overrides
        super().__init__(policy_path=policy_path)

    def load_policy_dirs(self, paths: Iterable[pathlib.PurePath]) -> None:
        assert len(paths) == 1
        path, = paths
        self.policy_path = path
        self.load_policy_dir(path)

    def load_policy_dir(self, dirpath: pathlib.Path) -> None:
        for path in filter_filepaths(dirpath.iterdir()):
            if path not in self.overrides:
                with path.open() as file:
                    self.load_policy_file(file, path)
        for path, content in self.overrides.items():
            if path.parent == dirpath and content is not None:
                self.load_policy_file(io.StringIO(content), path)

    def resolve_filepath(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ) -> Tuple[TextIO, pathlib.PurePath]:
        path = self.resolve_path(included_path)
        if path in self.overrides:
            if self.overrides[path] is None:
                raise exc.PolicySyntaxError(
                    filepath,
                    lineno,
                    "including a file that will be removed: {}".format(path),
                )
            return io.StringIO(self.overrides[path]), path
        return super().resolve_filepath(
            included_path, filepath=filepath, lineno=lineno
        )

    def handle_rule(self, rule, *, filepath, lineno):
        pass


class ToposortMixIn:
    """A helper for topological sorting the policy files"""
    # pylint can't deal with mixins
    # pylint: disable=no-member

    @enum.unique
    class State(enum.Enum):
        """State of topological sort algorithm"""

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
        """Yield (file, filename) in order suitable for mass-uploading.

        A file does not include anything from any file that follows in the
        sequence.

        *file* is an open()'d file for reading.
        """
        if not self.order:
            self.queue = set(self.included_paths.keys())
            self.queue.update(itertools.chain(self.included_paths.values()))
            while self.queue:
                self.dfs(self.queue.pop())

        for path in self.order:
            yield self.resolve_filepath(path, filepath=None, lineno=None)

    def dfs(self, node):
        """Perform one batch of topological sort"""
        self.state[node] = self.State.ON_PATH

        for nextnode in self.included_paths[node]:
            if self.state[nextnode] == self.State.ON_PATH:
                raise ValueError(
                    "circular include; {} → {}".format(
                        node.filepath, nextnode.filepath
                    )
                )
            if self.state[nextnode] == self.State.IN_ORDER:
                continue

            self.queue.discard(nextnode)
            self.dfs(nextnode)

        self.order.append(node)
        self.state[node] = self.State.IN_ORDER

    def save_included_path(self, included_path, *, filepath, lineno):
        """Store the vertex in the dependency graph.

        Only paths inside :py:attr:`policy_path` and ``include`` directory
        (as supported by Policy API) are considered.
        """

        key = self._path_to_key(included_path)

        if "/" in key and (
            not key.startswith("include/") or key.count("/") > 1
        ):
            raise PolicySyntaxError(
                filepath,
                lineno,
                "invalid path {}, only paths inside the directories {policypath} and "
                "{policypath}/include are considered".format(
                    included_path, policypath=POLICYPATH
                ),
            )

        self.included_paths[key].add(included_path)

    def handle_include(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ):
        # pylint: disable=missing-docstring
        logging.debug(
            "Toposorter.handle_include(included_path=%r, filepath=%r)",
            included_path,
            filepath,
        )
        self.save_included_path(included_path, filepath=filepath, lineno=lineno)
        super().handle_include(included_path, filepath=filepath, lineno=lineno) # type: ignore

    def handle_include_service(
        self,
        service,
        argument,
        included_path: pathlib.PurePosixPath,
        *,
        filepath,
        lineno
    ):
        # pylint: disable=missing-docstring
        logging.debug(
            "Toposorter.handle_include_service(included_path=%r, filepath=%r)",
            included_path,
            filepath,
        )
        self.save_included_path(included_path, filepath=filepath, lineno=lineno)
        super().handle_include_service( # type: ignore
            service, argument, included_path, filepath=filepath, lineno=lineno
        )

    def load_policy_file(self, file, filepath):
        # pylint: disable=missing-docstring,expression-not-assigned
        # add filepath as seen
        self.included_paths[self._path_to_key(filepath)]
        super().load_policy_file(file, filepath)


class StringLoader(AbstractFileLoader):
    """An in-memory loader used for tests

    Args:
        policy (dict or str): policy dictionary. The keys are filenames to be
            included. It should contain ``'__main__'`` key which is loaded. If
            the argument is :py:class:`str`, it behaves as it was dict's
            ``'__main__'``.
    """

    def __init__(self, *args, policy, **kwds):
        super().__init__(*args, **kwds)
        self.policy = policy

    def resolve_filepath(
        self,
        included_path,
        *,
        filepath,
        lineno,
    ) -> Tuple[TextIO, pathlib.PurePath]:
        """
        Raises:
            qrexec.exc.PolicySyntaxError: when wrong path is included
        """
        included_path = str(included_path)
        try:
            file = io.StringIO(self.policy[included_path])
        except KeyError as err:
            raise exc.PolicySyntaxError(
                filepath,
                lineno,
                "no such policy file: {!r}".format(included_path),
            ) from err
        return file, pathlib.PurePosixPath(included_path + "[in-memory]")

    def handle_include_dir(
        self, included_path: pathlib.PurePosixPath, *, filepath, lineno
    ):
        raise NotImplementedError(
            "!include-dir is unsupported in {}".format(type(self).__name__)
        )


class StringPolicy(ToposortMixIn, StringLoader, AbstractPolicy):
    """String policy, used for tests and loading single files as policy. It
    can be used to test most of the code paths used in policy parsing.

    >>> testpolicy = StringPolicy(policy={
    ...     '__main__': '!include policy2'
    ...     'policy2': '* * @anyvm @anyvm allow'})
    """

    def __init__(self, *, policy, policy_compat=None, **kwds):
        if not isinstance(policy, collections.abc.Mapping):
            policy = {"__main__": policy}
        super().__init__(policy=policy, **kwds)
        if policy_compat is None:
            policy_compat = {}
        self.policy_compat = policy_compat
        file, filepath = self.resolve_filepath(
            "__main__", filepath=None, lineno=None
        )
        with file:
            self.load_policy_file(file, filepath)

    def handle_compat40(self, *, filepath, lineno):
        """"""
        # late import for circular
        from .parser_compat import TestCompat40Loader

        subparser = TestCompat40Loader(master=self, policy=self.policy_compat)
        subparser.execute(filepath=filepath, lineno=lineno)
