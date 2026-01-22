" Vim support file to detect file types
" Language:     Qrexec Policy
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2026 Mar 03

autocmd BufRead,BufNewFile
      \ */qubes/policy.d/*.policy
      \ setfiletype qrexecpolicy

let s:inc = '\v^\s*!%(compat-4.0|include%(-dir|-service)?)'

let s:srv = '\S+'
let s:arg = '%(\*|\+\S*)'
let s:src = '%(\*|dom0|\@%(adminvm|anyvm|%(dispvm:%(\@tag:)\?|tag:)\S+|type:%(AdminVM|AppVM|DispVM|StandaloneVM|TemplateVM))|uuid:\S+)'
let s:tgt = '%(\*|dom0|\@(default|adminvm|anyvm|dispvm|%(dispvm:%(\@tag:)\?|tag:)\S+|type:%(AdminVM|AppVM|DispVM|StandaloneVM|TemplateVM))|uuid:\S+)'
let s:res = '%(allow|ask|deny)'

let s:pat = '\v^\s*' . s:srv . '\s+' . s:arg . '\s+' . s:src . '\s+' . s:tgt . '\s+' . s:res

autocmd BufRead,BufNewFile
      \ *.policy
      \ for i in range(1, 30) |
      \   if getline(i) =~# s:pat || getline(i) =~# s:inc |
      \     setfiletype qrexecpolicy |
      \     break |
      \   endif |
      \ endfor

" vim: sw=2 sts=2 et :
