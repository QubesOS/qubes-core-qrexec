function PrintErrors()
  if empty(v:errors)
    return
  endif
  let s:tmpfile = tempname()
  call writefile(v:errors, s:tmpfile)
  execute printf('silent !cat %s 1>&2', s:tmpfile)
  " Pretty error can be seen if 'q' is removed from the command line.
  echoerr v:errors
  return 1
endfunc


function End()
  syntax clear
  bw!
  return PrintErrors()
endfunction


" Source: https://github.com/vim/vim/blob/master/src/testdir/test_syntax.vim
" License: Vim
func AssertHighlightGroups(lnum, startcol, expected, trans = 1, msg = "")
  " Assert that the characters starting at a given (line, col)
  " sequentially match the expected highlight groups.
  " If groups are provided as a string, each character is assumed to be a
  " group and spaces represent no group, useful for visually describing tests.
  let l:expectedGroups = type(a:expected) == v:t_string
        \ ? a:expected->split('\zs')->map({_, v -> trim(v)})
        \ : a:expected
  let l:errors = 0
  let l:msg = (a:msg->empty() ? "" : a:msg .. ": ")
        \ .. "Wrong highlight group at " .. a:lnum .. ","

  for l:i in range(a:startcol, a:startcol + l:expectedGroups->len() - 1)
    let l:errors += synID(a:lnum, l:i, a:trans)
          \ ->synIDattr("name")
          \ ->assert_equal(l:expectedGroups[l:i - 1],
          \    l:msg .. l:i)
  endfor
endfunc


" Source: https://github.com/tpope/vim-scriptease/blob/master/autoload/scriptease.vim
function GetSynNames(line, col) abort
  return reverse(map(synstack(a:line, a:col), 'synIDattr(v:val, "name")'))
endfunction


function AssertSyntax(expected, line, col_start, col_stop = -1)
  if a:col_stop == -1
    call assert_equal(
      \ a:expected, GetSynNames(a:line, a:col_start),
      \ a:line .. ":" .. a:col_start)
    return
  endif
  for col in range(a:col_start, a:col_stop)
    call assert_equal(
      \ a:expected, GetSynNames(a:line, col), a:line .. ":" .. col)
  endfor
endfunction


function TestSyntaxQrexecpolicy()
  new qrexecpolicy.policy
  syntax on
  runtime syntax/qrexecpolicy.vim

  " TODO: add more tests
  eval AssertHighlightGroups(1, 1, ["qrexecpolicyServiceSpecific", "", "qrexecpolicyArgPrefixSpecific", "qrexecpolicyArg", "", "qrexecpolicySourceLiteral", "", "qrexecpolicyTargetLiteral", "", "qrexecpolicyResolutionDeny"], 1)
  call AssertSyntax(["qrexecpolicyServiceSpecific"], 1, 1)
  call AssertSyntax(["qrexecpolicyServiceSpecific"], 2, 1, 7)
  call AssertSyntax([], 2, 8)
  call AssertSyntax(["qrexecpolicyArgPrefixSpecific"], 2, 9)
  call AssertSyntax(["qrexecpolicyArg"], 2, 10, 17)
  call AssertSyntax([], 2, 18)
  call AssertSyntax(["qrexecpolicySourceLiteral"], 2, 19, 24)
  call AssertSyntax([], 2, 25)
  call AssertSyntax(["qrexecpolicyTargetLiteral"], 2, 26, 36)
  call AssertSyntax([], 2, 37)
  call AssertSyntax(["qrexecpolicyResolutionDeny"], 2, 38, 41)
  call AssertSyntax([], 2, 42)
  call AssertSyntax(["qrexecpolicyParamDenyBoolean"], 2, 43, 48)
  call AssertSyntax(["qrexecpolicyParamDenyBooleanAssign"], 2, 49)
  call AssertSyntax(["qrexecpolicyParamDenyBooleanArg"], 2, 50, 51)

  call End()
endfunction


function TestSyntaxQrexecpolicyservice()
  new qrexecpolicyservice.policy
  syntax on
  runtime syntax/qrexecpolicyservice.vim

  " TODO: add more tests
  call AssertSyntax(["qrexecpolicyServiceSpecific"], 1, 1)

  call End()
endfunction


function TestSyntaxQrexecconfig()
  new qrexecconfig.Service
  syntax on
  runtime syntax/qrexecconfig.vim

  " TODO: add more tests
  call AssertSyntax(["qrexecconfigComment"], 1, 1)

  call AssertSyntax(["qrexecconfigStringKey"], 7, 1, 10)
  call AssertSyntax(["qrexecconfigStringAssign"], 7, 11)
  call AssertSyntax(["qrexecconfigStringValue"], 7, 12, 17)

  call AssertSyntax([], 8, 11)
  call AssertSyntax(["qrexecconfigStringAssign"], 8, 12)
  call AssertSyntax([], 8, 13)
  call AssertSyntax(["qrexecconfigStringValue"], 8, 14, 19)

  call AssertSyntax(["qrexecconfigBooleanCompatKey"], 9, 1, 16)
  call AssertSyntax([], 9, 17)
  call AssertSyntax(["qrexecconfigBooleanAssignCompat"], 9, 18)
  call AssertSyntax([], 9, 19)
  call AssertSyntax(["qrexecconfigBooleanValueCompat"], 9, 20)

  call AssertSyntax(["qrexecconfigBooleanValueCompat"], 18, 22, 26)

  call AssertSyntax(["qrexecconfigBooleanKey"], 19, 1, 23)
  call AssertSyntax(["qrexecconfigBooleanKey"], 21, 1, 18)
  call AssertSyntax(["qrexecconfigBooleanKey"], 23, 1, 10)

  " TODO: failing here, test is correct, syntax is wrong
  " call AssertSyntax(["qrexecconfigIncompleteError"], 28, 1, 2)

  call AssertSyntax(["qrexecconfigKeyUnknownError"], 34, 1, 13)
  call AssertSyntax([], 34, 14)

  call AssertSyntax(["qrexecconfigKeyUnknownError"], 35, 1, 15)
  call AssertSyntax([], 35, 16)

  call AssertSyntax(["qrexecconfigKeyUnknownError"], 36, 1, 18)
  call AssertSyntax([], 36, 19)

  call AssertSyntax(["qrexecconfigKeyUnknownError"], 37, 1, 18)
  call AssertSyntax([], 37, 19)

  call AssertSyntax(["qrexecconfigIncompleteError"], 38, 1, 24)
  call AssertSyntax(["qrexecconfigIncompleteError"], 39, 1, 24)
  call AssertSyntax(["qrexecconfigIncompleteError"], 40, 1, 19)
  call AssertSyntax(["qrexecconfigKeyUnknownError"], 41, 1, 20)

  call AssertSyntax(["qrexecconfigIncompleteError"], 43, 1, 10)
  call AssertSyntax(["qrexecconfigIncompleteError"], 44, 1, 16)
  call AssertSyntax(["qrexecconfigIncompleteError"], 45, 1, 23)
  call AssertSyntax(["qrexecconfigIncompleteError"], 46, 1, 18)
  call AssertSyntax(["qrexecconfigIncompleteError"], 47, 1, 20)

  call AssertSyntax(["qrexecconfigKeyUnknownError"], 49, 1, 11)
  call AssertSyntax(["qrexecconfigKeyUnknownError"], 50, 1, 17)
  call AssertSyntax(["qrexecconfigKeyUnknownError"], 51, 1, 24)
  call AssertSyntax(["qrexecconfigKeyUnknownError"], 52, 1, 19)
  call AssertSyntax(["qrexecconfigKeyUnknownError"], 53, 1, 21)

  call AssertSyntax(["qrexecconfigStringKey"], 55, 1, 10)
  call AssertSyntax(["qrexecconfigStringAssign"], 55, 12)
  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 55, 13, 19)

  call AssertSyntax(["qrexecconfigStringKey"], 61, 1, 10)
  call AssertSyntax(["qrexecconfigStringAssign"], 61, 12)
  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 61, 14, 17)
  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 62, 14, 19)
  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 64, 15, 19)
  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 66, 14, 15)

  call AssertSyntax(["qrexecconfigStringValue"], 68, 12, 13)
  call AssertSyntax(["qrexecconfigStringValueError", "qrexecconfigStringValue"], 68, 14)
  call AssertSyntax(["qrexecconfigStringValue"], 68, 15, 18)

  call AssertSyntax(["qrexecconfigStringValue"], 69, 14)
  call AssertSyntax(["qrexecconfigStringValueError", "qrexecconfigStringValue"], 69, 15)
  call AssertSyntax(["qrexecconfigStringValue"], 69, 16)

  call AssertSyntax([], 71, 13)
  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 71, 14)
  call AssertSyntax([], 71, 15, 18)

  call AssertSyntax(["qrexecconfigStringAssign"], 72, 12)
  call AssertSyntax([], 72, 13)
  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 72, 14, 17)

  call AssertSyntax(["qrexecconfigStringValue"], 74, 16)
  call AssertSyntax(["qrexecconfigMustEndError"], 74, 17, 19)
  call AssertSyntax(["qrexecconfigStringValue"], 75, 16)
  call AssertSyntax(["qrexecconfigMustEndError"], 75, 17, 18)

  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 77, 14, 24)
  call AssertSyntax(["qrexecconfigStringValueUnknownError"], 78, 14, 24)

  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 80, 20)
  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 81, 20)
  call AssertSyntax(["qrexecconfigBooleanValueCompat"], 82, 20)
  call AssertSyntax(["qrexecconfigMustEndError"], 82, 21)
  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 83, 27, 28)
  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 84, 27, 29)
  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 85, 27, 28)

  call AssertSyntax(["qrexecconfigMustEndError"], 87, 25)
  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 88, 20, 24)
  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 89, 20, 23)
  call AssertSyntax([], 89, 24, 28)

  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 90, 27)
  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 91, 27)
  call AssertSyntax(["qrexecconfigBooleanValueUnknownError"], 95, 22)

  call End()
endfunction


function RunTests()
  execute "chdir" expand("%:p:h")
  " TODO: enable all tests
  " call TestSyntaxQrexecpolicy()
  " call TestSyntaxQrexecpolicyservice()
  call TestSyntaxQrexecconfig()
endfunction
