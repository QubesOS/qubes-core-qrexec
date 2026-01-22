" Vim indent file
" Language:     Qrexec Policy
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2023 May 15

if exists('b:did_indent')
  finish
endif

let b:did_indent = 1

if !exists("g:qrexec_recommended_style")
  let g:qrexec_recommended_style = 1
endif

let b:undo_indent = "
  \ setlocal indentexpr< indentkeys< autoindent< |
  \ setlocal smartindent< cindent< lisp< |
  \"

setlocal indentexpr= indentkeys=0#,!^F,o,O
setlocal autoindent nosmartindent nocindent nolisp

if g:qrexec_recommended_style == 1
  let b:undo_indent ..= "
    \ setlocal expandtab< tabstop< softtabstop< shiftwidth< |
    \"
  setlocal expandtab tabstop=2 softtabstop=2 shiftwidth=2
endif

" vim: sw=2 sts=2 et :
