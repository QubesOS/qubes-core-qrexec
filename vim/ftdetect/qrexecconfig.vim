" Vim support file to detect file types
" Language:     Qrexec Config
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2023 May 15

autocmd BufRead,BufNewFile /etc/qubes/rpc-config/*
      \ setfiletype qrexecconfig

" vim: sw=2 sts=2 et :
