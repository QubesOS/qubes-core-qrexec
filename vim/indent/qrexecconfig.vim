" Vim indent file
" Language:     Qrexec Config
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2023 May 15

if exists('b:did_indent')
  finish
endif

runtime! indent/qrexecpolicy.vim
let b:did_indent = 1

" vim: sw=2 sts=2 et :
