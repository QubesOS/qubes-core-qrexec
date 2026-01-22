" Vim syntax file
" Language:     Qrexec Policy Service
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2023 May 25

if exists("b:current_syntax")
  finish
endif

runtime! syntax/qrexecpolicy.vim
unlet b:current_syntax

let b:current_syntax = "qrexecpolicyservice"

" vim: sw=2 sts=2 et :
