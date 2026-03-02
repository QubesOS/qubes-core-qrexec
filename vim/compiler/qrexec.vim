vim9script

# Vim compiler file
# Compiler:     qubes-policy-lint
# Maintainer:   Ben Grande <ben@invisiblethingslab.com>
# License:      Vim (see :h license)
# Repository:   https://github.com/QubesOS/qubes-core-qrexec
# Last Change:  2026 Mar 02

if exists("g:current_compiler")
  finish
endif
g:current_compiler = "qrexec"

if exists(":CompilerSet") != 2
  command -nargs=* CompilerSet setlocal <args>
endif

CompilerSet makeencoding=utf-8
if &filetype ==# "qrexecpolicy"
  CompilerSet makeprg=qubes-policy-lint\ %
elseif &filetype ==# "qrexecpolicyservice"
  CompilerSet makeprg=qubes-policy-lint\ --include-service\ %
elseif &filetype ==# "qrexecconfig"
  # TODO: Add a standalone tool using libqrexec/toml.c
  # https://github.com/qubesos/qubes-issues/issues/9188
endif
CompilerSet errorformat=%f:%l:\ %trror:\ %m,
                       \%-G%.%#

# vim: sw=2 sts=2 et :
