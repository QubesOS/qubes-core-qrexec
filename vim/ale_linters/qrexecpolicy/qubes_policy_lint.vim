" Vim ALE lint plugin file
" Language:     Qrexec Policy and Qrexec Policy Service
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2023 May 26


call ale#Set('qrexecpolicy_qubes_policy_lint_executable', 'qubes-policy-lint')
call ale#Set('qrexecpolicy_qubes_policy_lint_options', '')

function! ale_linters#qrexecpolicy#qubes_policy_lint#GetCommand(buffer) abort
  let l:include_service = ''
  if &filetype ==# "qrexecpolicyservice"
    let l:include_service = ' --include-service '
  endif
  return '%e '
       \ . l:include_service
       \ . ale#Pad(ale#Var(a:buffer, 'qrexecpolicy_qubes_policy_lint_options'))
       \ . ' -'
endfunction

function! ale_linters#qrexecpolicy#qubes_policy_lint#Handle(buffer, lines) abort
  let l:output = []
  " -:12: error: invalid action: allw
  " 0 1   2      3
  let l:pattern = '\v^-:(\d+): (error): (.*)$'

  for l:match in ale#util#GetMatches(a:lines, l:pattern)

    let l:item = {
    \   'lnum': l:match[1],
    \   'type': 'E',
    \   'text': l:match[3],
    \}

    call add(l:output, l:item)
  endfor

  return l:output
endfunction

call ale#linter#Define('qrexecpolicy', {
  \ 'name': 'qubes-policy-lint',
  \ 'aliases': ['qubes-policy-lint'],
  \ 'executable': {b -> ale#Var(b, 'qrexecpolicy_qubes_policy_lint_executable')},
  \ 'command': function('ale_linters#qrexecpolicy#qubes_policy_lint#GetCommand'),
  \ 'callback': 'ale_linters#qrexecpolicy#qubes_policy_lint#Handle',
  \})

" vim: sw=2 sts=2 et :
