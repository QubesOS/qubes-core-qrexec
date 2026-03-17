vim9script

# Vim filetype plugin file
# Language:     Qrexec Policy
# Maintainer:   Ben Grande <ben@invisiblethingslab.com>
# License:      Vim (see :h license)
# Repository:   https://github.com/QubesOS/qubes-core-qrexec
# Last Change:  2026 Mar 02

if exists("b:did_ftplugin")
  finish
endif
b:did_ftplugin = 1

if !exists("g:qrexec_recommended_style")
  g:qrexec_recommended_style = 1
endif

b:undo_ftplugin = "
  \ setlocal fileformat< comments< commentstring< formatoptions< |
  \ setlocal textwidth< iskeyword< completefunc< omnifunc< |
  \ setlocal spell< spelllang< |
  \"

setlocal fileformat=unix
setlocal comments=:# commentstring=#\ %s
setlocal formatoptions& formatoptions-=t formatoptions+=jcrql
#                   !, +,  0-9,  @,  A-Z, _,   a-z
setlocal iskeyword=33,43,48-57,@-@,65-90,95,97-122
setlocal completefunc=g:qrexeccomplete#Complete
setlocal omnifunc=g:qrexeccomplete#Complete
setlocal spell
setlocal spelllang+=en_us,qrexec

if g:qrexec_recommended_style == 1
  b:undo_ftplugin ..= "
    \ setlocal textwidth< |
    \"
  setlocal textwidth=78
endif

if &filetype ==# "qrexecpolicy"
  compiler qrexec
elseif &filetype ==# "qrexecpolicyservice"
  compiler qrexec
  b:undo_ftplugin ..= "
    \ unlet b:ale_linter_aliases |
    \"
  b:ale_linter_aliases = ['qrexecpolicy']
elseif &filetype ==# "qrexecconfig"
  # TODO: Add a standalone tool using libqrexec/toml.c
  # https://github.com/qubesos/qubes-issues/issues/9188
endif

b:undo_ftplugin ..= "
  \ unlet b:dispatch |
  \"
b:dispatch = &makeprg

# vim: sw=2 sts=2 et :
