# Multifile policy

*DRAFT 20180905*

The aim of this improvement is to increase flexibility of qrexec policy
management. If user wishes to install a Qubes-based application, 

# The changes

## New file syntax

```
qrexec.Service  +ARGUMENT   SRCQUBE     DSTQUBE     {allow|deny|ask} [PARAM=VALUE [PARAM=VALUE ...]]
qrexec.Service  *           @anyvm      @adminvm    {allow|deny|ask} [PARAM=VALUE [PARAM=VALUE ...]]
*               *           @tag:tag1   @type:AppVM {allow|deny|ask} [PARAM=VALUE [PARAM=VALUE ...]]
```

`ARGUMENT` may be empty. A single `+` means just empty argument.

Comments are lines starting with `#` (possibly preceded by whitespace) and empty
lines (or containing only whitespace). Inline comments are not allowed.

Parameters should be separated by whitespace, separation by comma is no longer
supported. Rationale: simplicity.

Supported params for actions other than `deny` (*NO CHANGE*):
- `target` means the call is directed to this domain; see below for possible
- `user`
- `default_target` (only for `ask`)

Service may be specified as `*` (a single asterisk) which means "any service".
For that case, argument also has to be `*`.

### Qube specification

| token                 | SRCQUBE   | DSTQUBE   | target=   | orig. target |
| --------------------- | --------- | --------- | --------- | --------- |
| a literal name        | +         | +         | +         | +         |
| `@adminvm`            | +         | +         | +         | +         |
| `@anyvm`              | +         | +         | -         | -         |
| `@default`            | -         | +         | -         | +         |
| `@dispvm`             | -         | +         | +         | +         |
| `@dispvm:VMNAME`      | +         | +         | +         | +         |
| `@dispvm:@tag:TAG`    | +         | +         | -         | -         |
| `@tag:TAG`            | +         | +         | -         | -         |
| `@type:TYPE`          | +         | +         | -         | -         |

### Rationale for \*
Previously there was no possibility to ensure that a call is prohibited for any
argument, not just as a default and hoping that no-one allowed any particular
argument.

### Rationale for dropping comma as separator of params
Simplicity.

## New policy location

The files reside in `/etc/qubes/policy.d`. Files with `.` as first character
and/or files not ending with `.policy` are ignored.

Files ending with `.policy` must be named using only digits, latin lowercase,
underscore, full stop and hyphen (`0123456789abcdefghijklmnopqrstuvwxyz_.-`).
Invalid, not ignored files are considered configuration errors and cause any
qrexec call to be rejected.

Files are considered in lexicographical order of the "C" locale.

### Rationale for file name constraints

The command `ls` has locale-dependent order. Many locales have different sort
orders than "C" locale for mixed-case filenames. If multiple files share common
number (i.e. `70-<pkgname>`) and have mixed case, the order of evaluation may be
different than displayed by common tools and lead to confusion.

At least `pl_PL.UTF-8`, `de_DE.UTF-8` and `en_GB.UTF-8` have those problems
(the letters are ordered "aAbBcC...", cf. C locale "ABC...abc..."). There are
other locales with more severe problems, like `eesti` which has the letter `Z`
sorted differently, but those are not worked around here.

As to file name content (`.policy` suffix and first character other than `.`),
there are two reasons. First reason is, `ls` without `-a` or `-A` won't list
them. Second reason is, several editors (notably Vim) keep backup and/or swap
files together with edited files. Typically they won't parse correctly, so they
would cause errors. Effectively this would break any qrexec calls while the
policy file is opened for editing.

## New include syntax
```
!include FILEPATH
!include-dir DIRPATH
```

Those commands include files or directories. Symbolic links are followed.
Relative paths are relative to the base policy directory. There may be a limit
to include depth.

If the file at FILENAME does not exist or is not a file, policy check
immediately fails. If the directory at DIRPATH does not exist or is not
a directory, policy fails. If the directory is empty, a warning is logged and
policy check continues.

The character `@` was changed to `!`. This is to have difference between `@`
tokens which are used in actual rules and the tokens that actually changes line
syntax.

## New per-service include syntax
```
!include-service {qrexec.Service|*} {+ARGUMENT|*} FILENAME
```

The file referenced by FILENAME is in old syntax:
- there is no service and argument on the line
- `$` is accepted as part of tokens
- `@include` includes files with the same syntax;
  also valid with colon syntax (`$include:/file/path`).

The file is included only for this particular service. Argument field is
mandatory, but may be empty (single `+`) or catch-all `*`. FILENAME is included
only for that service with that argument. As with normal line, `*` is also
accepted for service field, and then only `*` is valid for argument.

This "old" syntax is fully supported and currently we don't intend to remove it,
as it is the only way to express policy for multiple services in one place. For
example it is used for Admin API, which consists of multiple calls which should
be managed together.

## Compatibility statement (R4.0)
```
!compat-4.0
```

This statement includes old policy emulating old behaviour. It reads files in
`/etc/qubes-rpc/policy` and adds rules found there. After each file for specific
argument (with `+` in filename) it also adds `deny` rules that were previously
implicit. Those rules are not added for non-specific files (without `+` in
filename) not to shadow the default policy.

This statement is transitional and will be unavailable in 5.0.

## New Policy API service: per-policy restore

The service `policy.RestoreService+SERVICE` restores a service, not an API. It
operates on `/etc/qubes/policy.d/40-policyapi` file. The content of the policy
should only include rules related to the SERVICE. Arguments are not constrained.

# Other ideas and options not included elsewhere

This section is a coredump of ideas I came upon while thinking this through.
Most of those are probably rubbish.

# An overview of policy files

By default we ship those files:

- `/etc/qubes/policy.d/30-user.policy`
- `/etc/qubes/policy.d/35-compat.policy`
- `/etc/qubes/policy.d/40-policyapi.policy`
- `/etc/qubes/policy.d/50-salt.policy`
- `/etc/qubes/policy.d/90-default.policy`

Administrators deploying their company policies may use
`/etc/qubes/policy/20-admin`.

Vendors providing packaged rules should use:
- `/etc/qubes/policy.d/60-<pkgname>.policy` for explicit deny rules
- `/etc/qubes/policy.d/70-<pkgname>.policy` for explicit allow rules
- `/etc/qubes/policy.d/80-<pkgname>.policy` for generic rules, possibly with `*`
  in the service name.

This is expected of vendors to avoid conflicts between different packages.

A non-numbered `README` file is shipped, with (commented) explanation. This file
should not contain any policy.

# Examples (informative)

## Support for both R4.x and R5.0

In R5.0 package include this transitional policy:

```
!include-service qrexec.Service +ARG1 /etc/qubes-rpc/qrexec.Service+ARG1
!include-service qrexec.Service +ARG2 /etc/qubes-rpc/qrexec.Service+ARG2
!include-service qrexec.Service *     /etc/qubes-rpc/qrexec.Service
```

Schedule policy rewrite after deprecating 4.x support.

<!-- vim: set ft=markdown tw=80 : -->
