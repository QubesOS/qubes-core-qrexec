" Vim support file to detect file types
" Language:     Qrexec Policy Service
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2024 Sep 25

autocmd BufRead,BufNewFile
      \ /etc/qubes/policy.d/include/*
      \ /run/qubes/policy.d/include/*
      \ setfiletype qrexecpolicyservice

" vim: sw=2 sts=2 et :
