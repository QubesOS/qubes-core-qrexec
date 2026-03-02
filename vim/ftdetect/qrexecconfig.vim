vim9script

# Vim support file to detect file types
# Language:     Qrexec Config
# Maintainer:   Ben Grande <ben@invisiblethingslab.com>
# License:      Vim (see :h license)
# Repository:   https://github.com/QubesOS/qubes-core-qrexec
# Last Change:  2026 Mar 03

autocmd BufRead,BufNewFile
      \ */qubes/rpc-config/*
      | if expand('%:t') !=# 'README'
      |   setfiletype qrexecconfig
      | endif

const PAT = '\v^%(wait-for-session|force-user|skip-service-descriptor|exit-on-(client|service)-eof)\s*\=\s*\S+'

autocmd BufRead,BufNewFile
      \ qubes.*.config
      | for i in range(1, 30)
      |   if getline(i) =~ PAT
      |     setfiletype qrexecconfig
      |     break
      |   endif
      | endfor

# vim: sw=2 sts=2 et :
