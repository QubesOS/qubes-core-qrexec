vim9script

# Vim syntax file
# Language:     Qrexec Policy Service
# Maintainer:   Ben Grande <ben@invisiblethingslab.com>
# License:      Vim (see :h license)
# Repository:   https://github.com/QubesOS/qubes-core-qrexec
# Last Change:  2026 Mar 09

if exists("b:current_syntax")
  finish
endif

b:qrexec_syntax_policyservice = 1
runtime! syntax/qrexecpolicy.vim
unlet b:current_syntax b:qrexec_syntax_policyservice

b:current_syntax = "qrexecpolicyservice"

# vim: sw=2 sts=2 et :
