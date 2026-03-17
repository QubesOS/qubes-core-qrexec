vim9script

# Vim support file to detect file types
# Language:     Qrexec Policy Service
# Maintainer:   Ben Grande <ben@invisiblethingslab.com>
# License:      Vim (see :h license)
# Repository:   https://github.com/QubesOS/qubes-core-qrexec
# Last Change:  2026 Mar 03

autocmd BufRead,BufNewFile
      \ */qubes/policy.d/include/*
      \ setfiletype qrexecpolicyservice

const INC = '\v^\s*!%(compat-4.0|include%(-dir|-service)?)'

const SRC = '%(\*|dom0|\@%(adminvm|anyvm|%(dispvm:%(\@tag:)\?|tag:)\S+|type:%(AdminVM|AppVM|DispVM|StandaloneVM|TemplateVM))|uuid:\S+)'
const TGT = '%(\*|dom0|\@(default|adminvm|anyvm|dispvm|%(dispvm:%(\@tag:)\?|tag:)\S+|type:%(AdminVM|AppVM|DispVM|StandaloneVM|TemplateVM))|uuid:\S+)'
const RES = '%(allow|ask|deny)'

const PAT = '\v^\s*' .. SRC .. '\s+' .. TGT .. '\s+' .. RES

autocmd BufRead,BufNewFile
      \ {*/policy.d/include/*,*_include_*}
      | for i in range(1, 30)
      |   if getline(i) =~# PAT || getline(i) =~# INC
      |     setfiletype qrexecpolicyservice
      |     break
      |   endif
      | endfor

# vim: sw=2 sts=2 et :
