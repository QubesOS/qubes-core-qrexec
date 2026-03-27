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


" Source: https://github.com/tpope/vim-scriptease/blob/master/autoload/scriptease.vim
function GetSynNames(line, col) abort
  return reverse(map(synstack(a:line, a:col), 'synIDattr(v:val, "name")'))
endfunction


function AssertSyntax(line, col, expected)
  for col in a:col
    call assert_equal(
      \ a:expected, GetSynNames(a:line, col), a:line .. ":" .. col)
  endfor
endfunction


function TestSyntaxQrexecpolicy()
  new qrexecpolicy.policy
  syntax on
  runtime syntax/qrexecpolicy.vim

  call AssertSyntax(1, [1], ["qrexecpolicyComment"])
  call AssertSyntax(3, [1], ["qrexecpolicyCommentModeline", "qrexecpolicyComment"])
  call AssertSyntax(9, range(6, 9), ["qrexecpolicyTodo", "qrexecpolicyComment"])

  call AssertSyntax(20, range(3, 9), ["qrexecpolicyServiceSpecific"])
  call AssertSyntax(20, [12], ["qrexecpolicyArgPrefixGeneric"])
  call AssertSyntax(20, range(15, 20), ["qrexecpolicySourceTokenSingle"])
  call AssertSyntax(20, range(23, 28), ["qrexecpolicyTargetTokenSingle"])
  call AssertSyntax(20, range(31, 34), ["qrexecpolicyResolutionDeny"])
  call AssertSyntax(20, range(37, 42), ["qrexecpolicyParamDenyBoolean"])

  call AssertSyntax(21, range(3, 9), ["qrexecpolicyServiceSpecific"])
  call AssertSyntax(23, [3], ["qrexecpolicyServiceGeneric"])

  call AssertSyntax(25, range(3, 14), ["qrexecpolicyInclDir"])
  call AssertSyntax(25, range(26, 29), ["qrexecpolicyInclFilePath"])

  call AssertSyntax(26, range(3, 18), ["qrexecpolicyInclService"])
  call AssertSyntax(26, [21], ["qrexecpolicyInclServiceGeneric"])
  call AssertSyntax(26, [24], ["qrexecpolicyInclArgPrefixGeneric"])
  call AssertSyntax(26, range(26, 29), ["qrexecpolicyInclFilePath"])

  call AssertSyntax(27, [21], ["qrexecpolicyInclServiceSpecific"])

  call AssertSyntax(31, range(1, 11), ["qrexecpolicyCompat"])

  call AssertSyntax(38, range(36, 49), ["qrexecpolicyInclArg"])

  call AssertSyntax(42, range(33, 41), ["qrexecpolicyParamAllowBoolean"])
  call AssertSyntax(42, range(43, 45), ["qrexecpolicyParamAllowBooleanArg"])
  call AssertSyntax(42, range(47, 50), ["qrexecpolicyParamAllowNormal"])
  call AssertSyntax(42, range(52, 55), ["qrexecpolicyParamAllowNormalArg"])
  call AssertSyntax(42, range(57, 62), ["qrexecpolicyParamAllowTarget"])
  call AssertSyntax(42, range(64, 70), ["qrexecpolicyParamAllowTargetArgLiteral"])

  call AssertSyntax(43, range(72, 85), ["qrexecpolicyParamAskTarget"])
  call AssertSyntax(43, range(87, 90), ["qrexecpolicyParamAskTargetArgLiteral"])

  call AssertSyntax(47, range(54, 61), ["qrexecpolicyParamAllowTargetArgTokenSingle"])
  call AssertSyntax(48, range(20, 26), ["qrexecpolicyArg"])
  call AssertSyntax(48, range(55, 61), ["qrexecpolicyParamAllowTargetArgTokenCombo"])
  call AssertSyntax(48, range(62, 65), ["qrexecpolicyParamAllowTargetArgTokenComboArg"])
  call AssertSyntax(49, range(54, 66), ["qrexecpolicyParamAllowTargetArgUuid"])
  call AssertSyntax(50, range(54, 58), ["qrexecpolicyParamAllowTargetArgUuid"])
  call AssertSyntax(51, range(76, 83), ["qrexecpolicyParamAskTargetArgTokenSingle"])
  call AssertSyntax(52, range(52, 59), ["qrexecpolicyParamAskTargetArgTokenCombo"])
  call AssertSyntax(52, range(60, 63), ["qrexecpolicyParamAskTargetArgTokenComboArg"])
  call AssertSyntax(52, range(80, 86), ["qrexecpolicyParamAskTargetArgTokenSingle"])

  call AssertSyntax(58, range(21, 28), ["qrexecpolicySourceTokenSingle"])
  call AssertSyntax(59, range(21, 26), ["qrexecpolicySourceTokenSingle"])
  call AssertSyntax(59, range(21, 26), ["qrexecpolicySourceTokenSingle"])
  call AssertSyntax(60, range(21, 26), ["qrexecpolicySourceLiteral"])
  call AssertSyntax(60, range(41, 48), ["qrexecpolicyTargetTokenSingle"])
  call AssertSyntax(61, range(41, 47), ["qrexecpolicyTargetTokenSingle"])
  call AssertSyntax(62, range(29, 34), ["qrexecpolicySourceTokenComboNormalArg"])
  call AssertSyntax(63, range(21, 33), ["qrexecpolicySourceTokenComboNormal"])
  call AssertSyntax(63, range(34, 39), ["qrexecpolicySourceTokenComboNormalArg"])
  call AssertSyntax(64, range(21, 25), ["qrexecpolicySourceTokenComboNormal"])
  call AssertSyntax(64, range(26, 31), ["qrexecpolicySourceTokenComboNormalArg"])
  for rule in range(65, 69)
    call AssertSyntax(rule, range(21, 26), ["qrexecpolicySourceTokenComboType"])
    call AssertSyntax(rule, [27], ["qrexecpolicySourceTokenComboTypeArg"])
  endfor

  call AssertSyntax(70, range(21, 25), ["qrexecpolicySourceUuid"])
  call AssertSyntax(70, range(26, 61), ["qrexecpolicySourceUuidArg"])

  call AssertSyntax(80, range(12, 14), ["qrexecpolicyMustEndError"])
  call AssertSyntax(82, range(14, 17), ["qrexecpolicyMustEndError"])
  call AssertSyntax(83, range(21, 24), ["qrexecpolicyMustEndError"])
  call AssertSyntax(84, range(26, 29), ["qrexecpolicyMustEndError"])

  call AssertSyntax(92, range(1, 3), ["qrexecpolicyRuleIncomplete"])
  call AssertSyntax(95, [6], ["qrexecpolicyArgPrefixIncomplete"])
  call AssertSyntax(102, range(10, 15), ["qrexecpolicySourceIncomplete"])
  call AssertSyntax(104, range(17, 22), ["qrexecpolicyTargetIncomplete"])
  call AssertSyntax(106, [18], ["qrexecpolicyInclServiceIncomplete"])
  call AssertSyntax(107, range(18, 24), ["qrexecpolicyInclServiceIncomplete"])
  call AssertSyntax(108, range(26, 33), ["qrexecpolicyInclArgPrefixIncomplete"])

  call AssertSyntax(99, range(6, 7), ["qrexecpolicyArgPrefixGenericError", "qrexecpolicyArgPrefixGeneric"])
  call AssertSyntax(100, range(6, 7), ["qrexecpolicyArgPrefixUnknownError"])
  call AssertSyntax(101, range(6, 8), ["qrexecpolicyArgPrefixUnknownError"])
  for rule in range(114, 117)
    call AssertSyntax(rule, range(26, 27), ["qrexecpolicyInclArgPrefixUnknownError"])
  endfor

  call AssertSyntax(123, range(26, 34), ["qrexecpolicyParamDupNotifyError"])
  call AssertSyntax(124, range(51, 60), ["qrexecpolicyParamDupNotifyError"])
  call AssertSyntax(125, range(46, 64), ["qrexecpolicyParamDupDefaulttargetError"])

  call AssertSyntax(128, [3], ["qrexecpolicyArgPrefixUnknownError"])
  call AssertSyntax(129, range(3, 4), ["qrexecpolicyArgPrefixGenericError", "qrexecpolicyArgPrefixGeneric"])
  call AssertSyntax(137, range(6, 8), ["qrexecpolicyArgPrefixGenericError", "qrexecpolicyArgPrefixGeneric"])
  call AssertSyntax(146, range(5, 6), ["qrexecpolicyLiteralError", "qrexecpolicySourceLiteral"])
  call AssertSyntax(157, range(19, 20), ["qrexecpolicyLiteralError", "qrexecpolicyTargetLiteral"])

  call AssertSyntax(160, [5], ["qrexecpolicyLiteralError", "qrexecpolicySourceLiteral"])
  call AssertSyntax(161, [5], ["qrexecpolicyLiteralError", "qrexecpolicySourceLiteral"])
  call AssertSyntax(164, range(23, 33), ["qrexecpolicyTokenComboTypeArgError", "qrexecpolicyTargetTokenComboTypeArg"])
  call AssertSyntax(167, [5], ["qrexecpolicyLiteralError", "qrexecpolicySourceLiteral"])
  call AssertSyntax(168, [5], ["qrexecpolicyLiteralError", "qrexecpolicySourceLiteral"])

  call AssertSyntax(176, range(26, 34), ["qrexecpolicyParamDenyUnknownError"])
  call AssertSyntax(176, range(39, 42), ["qrexecpolicyParamDenyUnknownError"])
  call AssertSyntax(176, range(49, 54), ["qrexecpolicyParamDenyUnknownError"])
  call AssertSyntax(176, range(63, 76), ["qrexecpolicyParamDenyUnknownError"])

  call AssertSyntax(177, range(26, 34), ["qrexecpolicyParamAllowBoolean"])
  call AssertSyntax(177, range(39, 42), ["qrexecpolicyParamAllowNormal"])
  call AssertSyntax(177, range(49, 54), ["qrexecpolicyParamAllowTarget"])
  call AssertSyntax(177, range(63, 76), ["qrexecpolicyParamAllowUnknownError"])

  call AssertSyntax(178, range(26, 34), ["qrexecpolicyParamAskBoolean"])
  call AssertSyntax(178, range(39, 42), ["qrexecpolicyParamAskNormal"])
  call AssertSyntax(178, range(49, 54), ["qrexecpolicyParamAskTarget"])
  call AssertSyntax(178, range(63, 76), ["qrexecpolicyParamAskTarget"])

  call AssertSyntax(181, range(15, 20), ["qrexecpolicyParamAskUnknownError"])
  call AssertSyntax(181, range(23, 31), ["qrexecpolicyParamAskUnknownError"])
  call AssertSyntax(181, range(34, 37), ["qrexecpolicyParamAskUnknownError"])
  call AssertSyntax(181, range(40, 45), ["qrexecpolicyParamAskUnknownError"])
  call AssertSyntax(181, range(48, 61), ["qrexecpolicyParamAskUnknownError"])

  call AssertSyntax(185, range(24, 25), ["qrexecpolicyParamAskUnknownError"])

  call End()
endfunction


function TestSyntaxQrexecpolicyservice()
  new qrexecpolicyservice.policy
  syntax on
  runtime syntax/qrexecpolicyservice.vim

  call AssertSyntax(16, range(4, 9), ["qrexecpolicySourceTokenSingle", "qrexecpolicySourcePolicyService"])
  call AssertSyntax(16, range(15, 20), ["qrexecpolicyTargetTokenSingle"])
  call AssertSyntax(16, range(23, 26), ["qrexecpolicyResolutionDeny"])

  call AssertSyntax(17, range(4, 9), ["qrexecpolicySourceLiteral", "qrexecpolicySourcePolicyService"])
  call AssertSyntax(17, range(15, 18), ["qrexecpolicyTargetLiteral"])
  call AssertSyntax(17, range(23, 26), ["qrexecpolicyResolutionDeny"])

  call AssertSyntax(18, [4], ["qrexecpolicySourceGeneric", "qrexecpolicySourcePolicyService"])
  call AssertSyntax(18, [15], ["qrexecpolicyTargetGeneric"])
  call AssertSyntax(18, range(23, 26), ["qrexecpolicyResolutionDeny"])

  call AssertSyntax(19, range(4, 11), ["qrexecpolicyInclFile"])
  call AssertSyntax(19, range(23, 26), ["qrexecpolicyInclFilePath"])

  call AssertSyntax(63, range(1, 11), ["qrexecpolicyRuleIncomplete"])

  call AssertSyntax(64, [13], ["qrexecpolicyInclFilePath"])
  call AssertSyntax(64, range(14, 17), ["qrexecpolicyMustEndError"])

  call AssertSyntax(65, [1], ["qrexecpolicyLiteralError", "qrexecpolicySourceLiteral", "qrexecpolicySourcePolicyService"])
  call AssertSyntax(66, [1], ["qrexecpolicyLiteralError", "qrexecpolicySourceLiteral", "qrexecpolicySourcePolicyService"])

  call AssertSyntax(70, range(4, 7), ["qrexecpolicyRuleIncomplete"])

  call AssertSyntax(72, [1], ["qrexecpolicyRuleIncomplete"])

  call AssertSyntax(74, range(8, 13), ["qrexecpolicyTargetIncomplete"])

  call AssertSyntax(76, range(13, 21), ["qrexecpolicyResolutionError", "qrexecpolicyResolutionUnknownError"])
  call AssertSyntax(76, range(13, 21), ["qrexecpolicyResolutionError", "qrexecpolicyResolutionUnknownError"])

  call End()
endfunction


function TestSyntaxQrexecconfig()
  new qrexecconfig.Service
  syntax on
  runtime syntax/qrexecconfig.vim

  call AssertSyntax(1, [1], ["qrexecconfigComment"])

  call AssertSyntax(7, range(1,10), ["qrexecconfigStringKey"])
  call AssertSyntax(7, [11], ["qrexecconfigStringAssign"])
  call AssertSyntax(7, range(12,17), ["qrexecconfigStringValue"])

  call AssertSyntax(8, [11], [])
  call AssertSyntax(8, [12], ["qrexecconfigStringAssign"])
  call AssertSyntax(8, [13], [])
  call AssertSyntax(8, range(14, 19), ["qrexecconfigStringValue"])

  call AssertSyntax(9, range(1, 16), ["qrexecconfigBooleanCompatKey"])
  call AssertSyntax(9, [17], [])
  call AssertSyntax(9, [18], ["qrexecconfigBooleanAssignCompat"])
  call AssertSyntax(9, [19], [])
  call AssertSyntax(9, [20], ["qrexecconfigBooleanValueCompat"])

  call AssertSyntax(18, range(22, 26), ["qrexecconfigBooleanValueCompat"])

  call AssertSyntax(19, range(1, 23), ["qrexecconfigBooleanKey"])
  call AssertSyntax(21, range(1, 18), ["qrexecconfigBooleanKey"])
  call AssertSyntax(23, range(1, 10), ["qrexecconfigBooleanKey"])

  call AssertSyntax(28, [1], ["qrexecconfigIncompleteError"])

  call AssertSyntax(34, range(1, 13), ["qrexecconfigKeyUnknownError"])
  call AssertSyntax(34, [14], [])

  call AssertSyntax(35, range(1, 15), ["qrexecconfigKeyUnknownError"])
  call AssertSyntax(35, [16], [])

  call AssertSyntax(36, range(1, 18), ["qrexecconfigKeyUnknownError"])
  call AssertSyntax(36, [19], [])

  call AssertSyntax(37, range(1, 18), ["qrexecconfigKeyUnknownError"])
  call AssertSyntax(37, [19], [])

  call AssertSyntax(38, range(1, 24), ["qrexecconfigIncompleteError"])
  call AssertSyntax(39, range(1, 24), ["qrexecconfigIncompleteError"])
  call AssertSyntax(40, range(1, 19), ["qrexecconfigIncompleteError"])
  call AssertSyntax(41, range(1, 20), ["qrexecconfigKeyUnknownError"])

  call AssertSyntax(43, range(1, 10), ["qrexecconfigIncompleteError"])
  call AssertSyntax(44, range(1, 16), ["qrexecconfigIncompleteError"])
  call AssertSyntax(45, range(1, 23), ["qrexecconfigIncompleteError"])
  call AssertSyntax(46, range(1, 18), ["qrexecconfigIncompleteError"])
  call AssertSyntax(47, range(1, 20), ["qrexecconfigIncompleteError"])

  call AssertSyntax(49, range(1, 11), ["qrexecconfigKeyUnknownError"])
  call AssertSyntax(50, range(1, 17), ["qrexecconfigKeyUnknownError"])
  call AssertSyntax(51, range(1, 24), ["qrexecconfigKeyUnknownError"])
  call AssertSyntax(52, range(1, 19), ["qrexecconfigKeyUnknownError"])
  call AssertSyntax(53, range(1, 21), ["qrexecconfigKeyUnknownError"])

  call AssertSyntax(55, range(1, 10), ["qrexecconfigStringKey"])
  call AssertSyntax(55, [12], ["qrexecconfigStringAssign"])
  call AssertSyntax(55, range(13, 19), ["qrexecconfigStringValueUnknownError"])

  call AssertSyntax(61, range(1, 10), ["qrexecconfigStringKey"])
  call AssertSyntax(61, [12], ["qrexecconfigStringAssign"])
  call AssertSyntax(61, range(14, 17), ["qrexecconfigStringValueUnknownError"])
  call AssertSyntax(62, range(14, 19), ["qrexecconfigStringValueUnknownError"])
  call AssertSyntax(64, range(15, 19), ["qrexecconfigStringValueUnknownError"])
  call AssertSyntax(66, range(14, 15), ["qrexecconfigStringValueUnknownError"])

  call AssertSyntax(68, range(12, 13), ["qrexecconfigStringValue"])
  call AssertSyntax(68, [14], ["qrexecconfigStringValueError", "qrexecconfigStringValue"])
  call AssertSyntax(68, range(15, 18), ["qrexecconfigStringValue"])

  call AssertSyntax(69, [14], ["qrexecconfigStringValue"])
  call AssertSyntax(69, [15], ["qrexecconfigStringValueError", "qrexecconfigStringValue"])
  call AssertSyntax(69, [16], ["qrexecconfigStringValue"])

  call AssertSyntax(71, [13], [])
  call AssertSyntax(71, [14], ["qrexecconfigStringValueUnknownError"])
  call AssertSyntax(71, range(15, 18), [])

  call AssertSyntax(72, [12], ["qrexecconfigStringAssign"])
  call AssertSyntax(72, [13], [])
  call AssertSyntax(72, range(14, 17), ["qrexecconfigStringValueUnknownError"])

  call AssertSyntax(74, [16], ["qrexecconfigStringValue"])
  call AssertSyntax(74, range(17, 19), ["qrexecconfigMustEndError"])
  call AssertSyntax(75, [16], ["qrexecconfigStringValue"])
  call AssertSyntax(75, range(17, 18), ["qrexecconfigMustEndError"])

  call AssertSyntax(77, range(14, 24), ["qrexecconfigStringValueUnknownError"])
  call AssertSyntax(78, range(14, 24), ["qrexecconfigStringValueUnknownError"])

  call AssertSyntax(80, [20], ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(81, [20], ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(82, [20], ["qrexecconfigBooleanValueCompat"])
  call AssertSyntax(82, [21], ["qrexecconfigMustEndError"])
  call AssertSyntax(83, range(27, 28), ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(84, range(27, 29), ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(85, range(27, 28), ["qrexecconfigBooleanValueUnknownError"])

  call AssertSyntax(87, [25], ["qrexecconfigMustEndError"])
  call AssertSyntax(88, range(20, 24), ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(89, range(20, 23), ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(89, range(24, 28), [])

  call AssertSyntax(90, [27], ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(91, [27], ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(94, range(27, 31), ["qrexecconfigBooleanValue"])
  call AssertSyntax(94, range(32, 34), ["qrexecconfigMustEndError"])
  call AssertSyntax(95, range(22, 27), ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(96, [22], ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(97, [22], ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(98, range(23, 27), ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(99, [23], ["qrexecconfigBooleanValueUnknownError"])
  call AssertSyntax(100, [23], ["qrexecconfigBooleanValueUnknownError"])

  call End()
endfunction


function RunTests()
  execute "chdir" expand("%:p:h")
  call TestSyntaxQrexecpolicy()
  call TestSyntaxQrexecpolicyservice()
  call TestSyntaxQrexecconfig()
endfunction
