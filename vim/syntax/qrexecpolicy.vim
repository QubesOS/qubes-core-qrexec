" Vim syntax file
" Language:     Qrexec Policy
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2024 Oct 11


" Section: To do
" TODO: Because it involves multiple fields, a previous one requiring a later
"       one, how can a previous field indicate that it is missing a later but
"       not subsequent field without being confusing for the user?
"   Allow: For @default rule must specify target= option; and
"   Ask: For @default rule must specify target= option, else we get:
"        'no target is available to choose from';


" Section: Summary
"
" Implementation:
"   Correctness:
"     Catch All Fields: All fields must be in a syntax item;
"     Known Field Value: Set of possible values that are permitted;
"     Literal Field Value: Range of characters that are permitted; and
"     Minimum Field Number: Warn on the last field if next field is missing.
"   Style:
"     Spell: @NoSpell is set per item to limit false negatives;
"     Line Breaks: Easier to read, copy and paste to other sections;
"     Incomplete Item: Unterminated rule; and
"     Unknown Item: Invalid value.
" Service:
"   Literal Name: char range; and
"   Catch All: '*', its argument must also be '*'.
" Argument:
"   Literal Name: char range; and
"   Catch All: '*', its argument must also be '*'.
" Source:
"   Literal Name: char range on name or uuid;
"   Catch All: '*';
"   Token Single: @adminvm, @anyvm; and
"   Token Combo: @dispvm:VMNAME, @dispvm:@tag:TAG, @tag:TAG, @type:TYPE.
" Target:
"   Literal Name: char range on name or uuid;
"   Catch All: '*';
"   Token Single: @adminvm, @anyvm, @default, @dispvm; and
"   Token Combo: @dispvm:VMNAME, @dispvm:@tag:TAG, @tag:TAG, @type:TYPE.
" Resolution: deny, allow and ask.
" Parameter:
"   Autostart: yes, no;
"   Notify: yes, no;
"   User: char range;
"   Target: char range, uuid, '*', @adminvm, @dispvm, @dispvm:VMNAME,
"   @dispvm:uuid:; and
"   Default Target: char range uuid, '*', @adminvm, @dispvm, @dispvm:VMNAME
"   @dispvm:uuid.
" Parameters Verification:
"   Duplicated Parameters: forbidden;
"   Deny: notify=;
"   Allow: previous parameters, autostart=, user= and target=; and
"   Ask: previous parameters + default_target=.
" Token Argument Verification:
"   Type: AdminVM, AppVM, DispVM, StandaloneVM, TemplateVM;
"   Tag: char range; and
"   Name: char range.
"   UUID: char range with strict format


" Section: Bootstrap
if exists("b:current_syntax")
  finish
endif

let s:cpo_save = &cpo
set cpo&vim


" Section: Cluster
syn cluster qrexecpolicyInclServiceGroup
  \ add=qrexecpolicyInclServiceIncomplete
  \ add=qrexecpolicyInclServiceGeneric
  \ add=qrexecpolicyInclServiceSpecific

syn cluster qrexecpolicyInclArgPrefixGenericGroup
  \ add=qrexecpolicyInclArgPrefixUnknownError
  \ add=qrexecpolicyInclArgPrefixIncomplete
  \ add=qrexecpolicyInclArgPrefixGeneric

syn cluster qrexecpolicyInclArgPrefixSpecificGroup
  \ add=@qrexecpolicyInclArgPrefixGenericGroup
  \ add=qrexecpolicyInclArgPrefixSpecific

syn cluster qrexecpolicyArgPrefixGenericGroup
  \ add=qrexecpolicyArgPrefixUnknownError
  \ add=qrexecpolicyArgPrefixIncomplete
  \ add=qrexecpolicyArgPrefixGenericIncomplete
  \ add=qrexecpolicyArgPrefixGeneric

syn cluster qrexecpolicyArgPrefixSpecificGroup
  \ add=@qrexecpolicyArgPrefixGenericGroup
  \ add=qrexecpolicyArgPrefixSpecific

syn cluster qrexecpolicySourceGroup
  \ add=qrexecpolicySourceIncomplete
  \ add=qrexecpolicySourceLiteral
  \ add=qrexecpolicySourceGeneric
  \ add=qrexecpolicySourceTokenSingle
  \ add=qrexecpolicySourceTokenComboNormal
  \ add=qrexecpolicySourceTokenComboType
  \ add=qrexecpolicySourceUuid

syn cluster qrexecpolicyTargetGroup
  \ add=qrexecpolicyTargetIncomplete
  \ add=qrexecpolicyTargetLiteral
  \ add=qrexecpolicyTargetGeneric
  \ add=qrexecpolicyTargetTokenSingle
  \ add=qrexecpolicyTargetTokenComboNormal
  \ add=qrexecpolicyTargetTokenComboType
  \ add=qrexecpolicyTargetUuid

syn cluster qrexecpolicyResolutionGroup
  \ add=qrexecpolicyResolutionUnknownError
  \ add=qrexecpolicyResolutionDeny
  \ add=qrexecpolicyResolutionAsk
  \ add=qrexecpolicyResolutionAllow

syn cluster qrexecpolicyParamDenyGroup
  \ add=qrexecpolicyParamDenyUnknownError
  \ add=qrexecpolicyParamDenyBoolean
  \ add=@qrexecpolicyParamDenyDupErrorGroup
syn cluster qrexecpolicyParamAskGroup
  \ add=qrexecpolicyParamAskUnknownError
  \ add=qrexecpolicyParamAskNormal
  \ add=qrexecpolicyParamAskBoolean
  \ add=qrexecpolicyParamAskTarget
  \ add=@qrexecpolicyParamAskDupErrorGroup
syn cluster qrexecpolicyParamAllowGroup
  \ add=qrexecpolicyParamAllowUnknownError
  \ add=qrexecpolicyParamAllowNormal
  \ add=qrexecpolicyParamAllowBoolean
  \ add=qrexecpolicyParamAllowTarget
  \ add=@qrexecpolicyParamAllowDupErrorGroup

syn cluster qrexecpolicyParamAskTargetArgGroup
  \ add=qrexecpolicyParamAskTargetArgLiteral
  \ add=qrexecpolicyParamAskTargetArgTokenSingle
  \ add=qrexecpolicyParamAskTargetArgTokenCombo
  \ add=qrexecpolicyParamAskTargetArgUuid
syn cluster qrexecpolicyParamAllowTargetArgGroup
  \ add=qrexecpolicyParamAllowTargetArgLiteral
  \ add=qrexecpolicyParamAllowTargetArgTokenSingle
  \ add=qrexecpolicyParamAllowTargetArgTokenCombo
  \ add=qrexecpolicyParamAllowTargetArgUuid

syn cluster qrexecpolicyParamDenyDupErrorGroup
  \ add=qrexecpolicyParamDupNotifyError
  \ add=qrexecpolicyParamDupAutostartError
syn cluster qrexecpolicyParamAllowDupErrorGroup
  \ add=@qrexecpolicyParamDenyDupErrorGroup
  \ add=qrexecpolicyParamDupUserError
  \ add=qrexecpolicyParamDupTargetError
syn cluster qrexecpolicyParamAskDupErrorGroup
  \ add=@qrexecpolicyParamAllowDupErrorGroup
  \ add=qrexecpolicyParamDupDefaulttargetError

syn cluster qrexecpolicyCommentGroup
  \ add=qrexecpolicyComment
  \ add=qrexecpolicyCommentModeline
  \ add=qrexecpolicyTodo


" Section: Top level
syn match qrexecpolicyRuleIncomplete
  \ '^\s*\zs\S\+\ze\(\s\+\)\?$'
  \ contains=@NoSpell

if &filetype ==# "qrexecpolicy"
  syn match qrexecpolicyServiceSpecific
    \ '^\s*\zs\S\+\ze\s\+\S'
    \ contains=qrexecpolicyServiceSpecificError,@NoSpell
    \ nextgroup=@qrexecpolicyArgPrefixSpecificGroup
    \ skipwhite

  syn match qrexecpolicyServiceGeneric
    \ '^\s*\zs\*\ze\s\+\S'
    \ contains=qrexecpolicyServiceGenericError,@NoSpell
    \ nextgroup=@qrexecpolicyArgPrefixGenericGroup
    \ skipwhite

  syn match qrexecpolicyCompat
    \ '^\s*\zs!compat-4.0'
    \ contains=@NoSpell
    \ nextgroup=qrexecpolicyMustEndError

  syn match qrexecpolicyInclService
    \ '^\s*\zs!include-service\ze\s\+\S'
    \ contains=@NoSpell
    \ nextgroup=@qrexecpolicyInclServiceGroup
    \ skipwhite

  syn match qrexecpolicyInclDir
    \ '^\s*\zs!include-dir\ze\s\+\S'
    \ contains=@NoSpell
    \ nextgroup=qrexecpolicyInclFilePath
    \ skipwhite

elseif &filetype ==# "qrexecpolicyservice"
  syn match qrexecpolicySourcePolicyService
    \ '^\s*\zs\S\+\ze\s\+\S'
    \ contains=@NoSpell,@qrexecpolicySourceGroup
    \ nextgroup=@qrexecpolicyTargetGroup
    \ skipwhite

endif

syn match qrexecpolicyInclFile
  \ '^\s*\zs!include\ze\s\+\S'
  \ contains=@NoSpell
  \ nextgroup=qrexecpolicyInclFilePath
  \ skipwhite


" Section: Incl options
syn match qrexecpolicyInclServiceIncomplete
  \ '\S\+'
  \ contained
  \ contains=@NoSpell

syn match qrexecpolicyInclServiceGeneric
  \ '\*\ze\s\+\S'
  \ contained
  \ contains=qrexecpolicyServiceGenericError,@NoSpell
  \ nextgroup=@qrexecpolicyInclArgPrefixGenericGroup
  \ skipwhite

syn match qrexecpolicyInclServiceSpecific
  \ '[^[:space:]*]\S*\ze\s\+\S'
  \ contained
  \ contains=qrexecpolicyServiceSpecificError,@NoSpell
  \ nextgroup=@qrexecpolicyInclArgPrefixSpecificGroup
  \ skipwhite

syn match qrexecpolicyInclArgPrefixIncomplete
  \ '\S\+'
  \ contained
  \ contains=@NoSpell

syn match qrexecpolicyInclArgPrefixUnknownError
  \ '\S\+\ze\s\+\S'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=qrexecpolicyInclFilePath
  \ skipwhite

syn match qrexecpolicyInclArgPrefixGeneric
  \ '\s\@<=\*\S*\ze\s\+\S'
  \ contained
  \ contains=qrexecpolicyArgPrefixGenericError,@NoSpell
  \ nextgroup=qrexecpolicyInclFilePath
  \ skipwhite

syn match qrexecpolicyInclArgPrefixSpecific
  \ '+\ze\S*\s\+\S'
  \ contained
  \ contains=qrexecpolicyArgPrefixSpecificError
  \ nextgroup=qrexecpolicyInclArg
syn match qrexecpolicyInclArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyArgError,@NoSpell
  \ nextgroup=qrexecpolicyInclFilePath
  \ skipwhite

syn match qrexecpolicyInclFilePath
  \ '\S\+'
  \ contained
  \ contains=qrexecpolicyInclFilePathError,@NoSpell
  \ nextgroup=qrexecpolicyMustEndError

" Section: Arg
syn match qrexecpolicyArgPrefixIncomplete
  \ '\S\+'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=@qrexecpolicySourceGroup
  \ skipwhite

syn match qrexecpolicyArgPrefixUnknownError
  \ '\S\+\ze\s\+\S'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=@qrexecpolicySourceGroup
  \ skipwhite

syn match qrexecpolicyArgPrefixGeneric
  \ '\s\@<=\*\S*\ze\s\+\S'
  \ contained
  \ contains=qrexecpolicyArgPrefixGenericError,@NoSpell
  \ nextgroup=@qrexecpolicySourceGroup
  \ skipwhite

syn match qrexecpolicyArgPrefixSpecific
  \ '\s\@<=+\ze\S*\s\+\S'
  \ contained
  \ contains=qrexecpolicyArgPrefixSpecificError,@NoSpell
  \ nextgroup=qrexecpolicyArg
syn match qrexecpolicyArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyArgError,@NoSpell
  \ nextgroup=@qrexecpolicySourceGroup
  \ skipwhite


" Section: Source
syn match qrexecpolicySourceIncomplete
  \ '\S\+'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=@qrexecpolicyTargetGroup
  \ skipwhite

syn match qrexecpolicySourceLiteral
  \ '\S\+\ze\s\+\S'
  \ contained
  \ contains=qrexecpolicyLiteralError,@NoSpell
  \ nextgroup=@qrexecpolicyTargetGroup
  \ skipwhite

syn match qrexecpolicySourceGeneric
  \ '\*\ze\s\+\S'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=@qrexecpolicyTargetGroup
  \ skipwhite

syn match qrexecpolicySourceTokenSingle
  \ '@\(adminvm\|anyvm\)\ze\s\+\S'
  \ contained
  \ contains=qrexecpolicyTokenSingleError,@NoSpell
  \ nextgroup=@qrexecpolicyTargetGroup
  \ skipwhite

syn match qrexecpolicySourceTokenComboNormal
  \ '@\(tag:\|dispvm:\(@tag:\)\?\)\ze\S\+\s\+\S'
  \ contained
  \ contains=qrexecpolicyTokenComboError,@NoSpell
  \ nextgroup=qrexecpolicySourceTokenComboNormalArg
syn match qrexecpolicySourceTokenComboNormalArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyTokenComboArgError,@NoSpell
  \ nextgroup=@qrexecpolicyTargetGroup
  \ skipwhite

syn match qrexecpolicySourceTokenComboType
  \ '@type:\ze\S\+\s\+\S'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=qrexecpolicySourceTokenComboTypeArg
syn match qrexecpolicySourceTokenComboTypeArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyTokenComboTypeArgError,@NoSpell
  \ nextgroup=@qrexecpolicyTargetGroup
  \ skipwhite

syn match qrexecpolicySourceUuid
  \ '\(@dispvm:\)\?uuid:\ze\S\+\s\+\S'
  \ contained
  \ contains=qrexecpolicyUuidError,@NoSpell
  \ nextgroup=qrexecpolicySourceUuidArg
syn match qrexecpolicySourceUuidArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyUuidArgError,@NoSpell
  \ nextgroup=@qrexecpolicyTargetGroup
  \ skipwhite


" Section: Target
syn match qrexecpolicyTargetIncomplete
  \ '\S\+'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=@qrexecpolicyResolutionGroup
  \ skipwhite

syn match qrexecpolicyTargetLiteral
  \ '\S\+\ze\s\+\S'
  \ contained
  \ contains=qrexecpolicyLiteralError,@NoSpell
  \ nextgroup=@qrexecpolicyResolutionGroup
  \ skipwhite

syn match qrexecpolicyTargetGeneric
  \ '\*\ze\s\+\S'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=@qrexecpolicyResolutionGroup
  \ skipwhite

syn match qrexecpolicyTargetTokenSingle
  \ '@\(adminvm\|anyvm\|default\|dispvm\)\ze\s\+\S'
  \ contained
  \ contains=qrexecpolicyTokenSingleError,@NoSpell
  \ nextgroup=@qrexecpolicyResolutionGroup
  \ skipwhite

syn match qrexecpolicyTargetTokenComboNormal
  \ '@\(tag:\|dispvm:\(@tag:\)\?\)\ze\S\+\s\+\S'
  \ contained
  \ contains=qrexecpolicyTokenComboError,@NoSpell
  \ nextgroup=qrexecpolicyTargetTokenComboNormalArg
syn match qrexecpolicyTargetTokenComboNormalArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyTokenComboArgError,@NoSpell
  \ nextgroup=@qrexecpolicyResolutionGroup
  \ skipwhite

syn match qrexecpolicyTargetTokenComboType
  \ '@type:\ze\S\+\s\+\S'
  \ contained
  \ contains=@NoSpell
  \ nextgroup=qrexecpolicyTargetTokenComboTypeArg
syn match qrexecpolicyTargetTokenComboTypeArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyTokenComboTypeArgError,@NoSpell
  \ nextgroup=@qrexecpolicyResolutionGroup
  \ skipwhite

syn match qrexecpolicyTargetUuid
  \ '\(@dispvm:\)\?uuid:\ze\S\+\s\+\S'
  \ contained
  \ contains=qrexecpolicyUuidError,@NoSpell
  \ nextgroup=qrexecpolicyTargetUuidArg
syn match qrexecpolicyTargetUuidArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyUuidArgError,@NoSpell
  \ nextgroup=@qrexecpolicyResolutionGroup
  \ skipwhite


" Section: Resolution
syn match qrexecpolicyResolutionUnknownError
  \ '\s*\zs\S\+'
  \ contained
  \ contains=qrexecpolicyResolutionError

syn match qrexecpolicyResolutionDeny
  \ '\s*\zsdeny\(\s\+\|$\)'
  \ contained
  \ contains=qrexecpolicyResolutionError,@NoSpell
  \ nextgroup=@qrexecpolicyParamDenyGroup
  \ skipwhite

syn match qrexecpolicyResolutionAllow
  \ '\s*\zsallow\(\s\+\|$\)'
  \ contained
  \ contains=qrexecpolicyResolutionError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAllowGroup
  \ skipwhite

syn match qrexecpolicyResolutionAsk
  \ '\s*\zsask\(\s\+\|$\)'
  \ contained
  \ contains=qrexecpolicyResolutionError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite


" Section: Param UnknownError
syn match qrexecpolicyParamDenyUnknownError
  \ '\S\+'
  \ contained
  \ contains=qrexecpolicyParamError
  \ nextgroup=@qrexecpolicyParamDenyGroup
  \ skipwhite

syn match qrexecpolicyParamAllowUnknownError
  \ '\S\+'
  \ contained
  \ contains=qrexecpolicyParamError
  \ nextgroup=@qrexecpolicyParamAllowGroup
  \ skipwhite

syn match qrexecpolicyParamAskUnknownError
  \ '\S\+'
  \ contained
  \ contains=qrexecpolicyParamError
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite


" Section: Param Normal
syn match qrexecpolicyParamAllowNormal
  \ '\(user\ze=\S\+\)'
  \ contained
  \ contains=qrexecpolicyParamError,@NoSpell
  \ nextgroup=qrexecpolicyParamAllowNormalAssign
syn match qrexecpolicyParamAllowNormalAssign
  \ '='
  \ contained
  \ nextgroup=qrexecpolicyParamAllowNormalArg
syn match qrexecpolicyParamAllowNormalArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyParamArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAllowGroup
  \ skipwhite

syn match qrexecpolicyParamAskNormal
  \ '\(user\ze=\S\+\)'
  \ contained
  \ contains=qrexecpolicyParamError
  \ nextgroup=qrexecpolicyParamAskNormalAssign
syn match qrexecpolicyParamAskNormalAssign
  \ '='
  \ contained
  \ nextgroup=qrexecpolicyParamAskNormalArg
syn match qrexecpolicyParamAskNormalArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyParamArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite

" Section: Param Boolean
syn match qrexecpolicyParamDenyBoolean
  \ '\(notify\ze=\S\+\)'
  \ contained
  \ contains=qrexecpolicyParamError,@NoSpell
  \ nextgroup=qrexecpolicyParamDenyBooleanAssign
syn match qrexecpolicyParamDenyBooleanAssign
  \ '='
  \ contained
  \ nextgroup=qrexecpolicyParamDenyBooleanArg
syn match qrexecpolicyParamDenyBooleanArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyParamBooleanArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamDenyGroup
  \ skipwhite

syn match qrexecpolicyParamAllowBoolean
  \ '\(autostart\ze=\S\+\|notify\ze=\S\+\)'
  \ contained
  \ contains=qrexecpolicyParamError,@NoSpell
  \ nextgroup=qrexecpolicyParamAllowBooleanAssign
syn match qrexecpolicyParamAllowBooleanAssign
  \ '='
  \ contained
  \ nextgroup=qrexecpolicyParamAllowBooleanArg
syn match qrexecpolicyParamAllowBooleanArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyParamBooleanArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAllowGroup
  \ skipwhite

syn match qrexecpolicyParamAskBoolean
  \ '\(autostart\ze=\S\+\|notify\ze=\S\+\)'
  \ contained
  \ contains=qrexecpolicyParamError,@NoSpell
  \ nextgroup=qrexecpolicyParamAskBooleanAssign
syn match qrexecpolicyParamAskBooleanAssign
  \ '='
  \ contained
  \ nextgroup=qrexecpolicyParamAskBooleanArg
syn match qrexecpolicyParamAskBooleanArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyParamBooleanArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite


" Section: Param Target
syn match qrexecpolicyParamAllowTarget
  \ '\(target\ze=\S\+\)'
  \ contained
  \ contains=qrexecpolicyParamError,@NoSpell
  \ nextgroup=qrexecpolicyParamAllowTargetAssign
syn match qrexecpolicyParamAllowTargetAssign
  \ '='
  \ contained
  \ nextgroup=@qrexecpolicyParamAllowTargetArgGroup
syn match qrexecpolicyParamAllowTargetArgLiteral
  \ '\S\+'
  \ contained
  \ contains=qrexecpolicyParamArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAllowGroup
  \ skipwhite
syn match qrexecpolicyParamAllowTargetArgTokenSingle
  \ '@\(adminvm\|dispvm\)'
  \ contained
  \ contains=qrexecpolicyTokenSingleError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAllowGroup
  \ skipwhite
syn match qrexecpolicyParamAllowTargetArgTokenCombo
  \ '@\(dispvm:\)\ze\S\+'
  \ contained
  \ contains=qrexecpolicyTokenComboError,@NoSpell
  \ nextgroup=qrexecpolicyParamAllowTargetArgTokenComboArg
syn match qrexecpolicyParamAllowTargetArgTokenComboArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyTokenComboArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAllowGroup
  \ skipwhite
syn match qrexecpolicyParamAllowTargetArgUuid
  \ '\(@dispvm:\)\?uuid:\ze\S\+'
  \ contained
  \ contains=qrexecpolicyUuidError,@NoSpell
  \ nextgroup=qrexecpolicyParamAskTargetArgUuidArg
syn match qrexecpolicyParamAskTargetArgUuidArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyUuidArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite

syn match qrexecpolicyParamAskTarget
  \ '\(target\ze=\S\+\|default_target\ze=\S\+\)'
  \ contained
  \ contains=qrexecpolicyParamError,@NoSpell
  \ nextgroup=qrexecpolicyParamAskTargetAssign
syn match qrexecpolicyParamAskTargetAssign
  \ '='
  \ contained
  \ nextgroup=@qrexecpolicyParamAskTargetArgGroup
syn match qrexecpolicyParamAskTargetArgLiteral
  \ '\S\+'
  \ contained
  \ contains=qrexecpolicyParamArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite
syn match qrexecpolicyParamAskTargetArgTokenSingle
  \ '@\(adminvm\|dispvm\)'
  \ contained
  \ contains=qrexecpolicyTokenSingleError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite
syn match qrexecpolicyParamAskTargetArgTokenCombo
  \ '@\(dispvm:\)\ze\S\+'
  \ contained
  \ contains=qrexecpolicyTokenComboError,@NoSpell
  \ nextgroup=qrexecpolicyParamAskTargetArgTokenComboArg
syn match qrexecpolicyParamAskTargetArgTokenComboArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyTokenComboArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite
syn match qrexecpolicyParamAskTargetArgUuid
  \ '\(@dispvm:\)\?uuid:\ze\S\+'
  \ contained
  \ contains=qrexecpolicyUuidError,@NoSpell
  \ nextgroup=qrexecpolicyParamAskTargetArgUuidArg
syn match qrexecpolicyParamAskTargetArgUuidArg
  \ '\S*'
  \ contained
  \ contains=qrexecpolicyUuidArgError,@NoSpell
  \ nextgroup=@qrexecpolicyParamAskGroup
  \ skipwhite


" Section: Errors
syn match qrexecpolicyCharError
  \ '[^[:space:]0-9A-Za-z!=_@.*:+-]'
  \ containedin=ALLBUT,@qrexecpolicyCommentGroup,qrexecpolicyInclFilePath
syn match qrexecpolicyMustEndError
  \ '.*'
  \ contained
syn match qrexecpolicyInclFilePathError
  \ '[^0-9A-Za-z/_.+-]'
  \ contained
syn match qrexecpolicyServiceGenericError
  \ '\([^*]\|\*\*\)'
  \ contained
syn match qrexecpolicyServiceSpecificError
  \ '[^0-9A-Za-z_.-]'
  \ contained
syn match qrexecpolicyArgPrefixGenericError
  \ '\*\S\+'
  \ contained
  \ contains=@NoSpell
syn match qrexecpolicyArgPrefixSpecificError
  \ '[^0-9A-Za-z+_.-]'
  \ contained
syn match qrexecpolicyArgError
  \ '[^0-9A-Za-z+_.-]'
  \ contained
syn match qrexecpolicyUuidError
  \ '\v\s@<=((\@dispvm:)?uuid:)@!\S*'
  \ contained
syn match qrexecpolicyUuidArgError
  \ '\v(uuid:)@<=([0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\ze(\s|$))@!\S*'
  \ contained
syn match qrexecpolicyLiteralError
  \ '[^0-9A-Za-z_-]'
  \ contained
syn match qrexecpolicyTokenSingleError
  \ '[^a-z@]'
  \ contained
syn match qrexecpolicyTokenComboError
  \ '[^a-z@:]'
  \ contained
syn match qrexecpolicyTokenComboArgError
  \ '[^0-9A-Za-z_-]'
  \ contained
syn match qrexecpolicyTokenComboTypeArgError
  \ '\v(\@type:)@<=((AdminVM|AppVM|DispVM|StandaloneVM|TemplateVM)(\s|$))@!\S*'
  \ contained
syn match qrexecpolicyResolutionError
  \ '\v\s@<=((allow|deny|ask)(\s|$))@!\S*'
  \ contained
syn match qrexecpolicyParamError
  \ '[^a-z_]'
  \ contained
syn match qrexecpolicyParamBooleanArgError
  \ '\v\=@<=((yes|no)(\s|$))@!\S*'
  \ contained
syn match qrexecpolicyParamArgError
  \ '[^0-9A-Za-z_-]'
  \ contained
syn match qrexecpolicyParamDupUserError
  \ '\(\suser=\S\+.*\s\)\@<=user=\(\S*\)\?'
  \ contained
syn match qrexecpolicyParamDupNotifyError
  \ '\(\snotify=\S\+.*\s\)\@<=notify=\(\S*\)\?'
  \ contained
syn match qrexecpolicyParamDupAutostartError
  \ '\(\sautostart=\S\+.*\s\)\@<=autostart=\(\S*\)\?'
  \ contained
syn match qrexecpolicyParamDupTargetError
  \ '\(\starget=\S\+.*\s\)\@<=target=\(\S*\)\?'
  \ contained
syn match qrexecpolicyParamDupDefaulttargetError
  \ '\(\sdefault_target=\S\+.*\s\)\@<=default_target=\(\S*\)\?'
  \ contained


" Section: Comments
syn match qrexecpolicyComment
  \ '^\s*\zs#.*$'
  \ contains=@qrexecpolicyCommentGroup
syn match qrexecpolicyTodo
  \ '\s\+\zs\(TODO\|FIXME\|NOTE\|XXX\)\ze:\(\s\+\|$\)'
  \ contained
  \ contains=@NoSpell
syn match qrexecpolicyCommentModeline
  \ '^\s*\zs#\S*\s\+vim:.*$'
  \ contained
  \ contains=@NoSpell


" Section: Highlight
" Incl Group
hi def link qrexecpolicyCompat                         qrexecpolicyIncl
hi def link qrexecpolicyInclFile                       qrexecpolicyIncl
hi def link qrexecpolicyInclDir                        qrexecpolicyIncl
hi def link qrexecpolicyInclService                    qrexecpolicyIncl
hi def link qrexecpolicyInclServiceGeneric             qrexecpolicySpecialChar
hi def link qrexecpolicyInclArgPrefixGeneric           qrexecpolicyArgPrefix
hi def link qrexecpolicyInclArgPrefixSpecific          qrexecpolicyArgPrefix
hi def link qrexecpolicyInclArg                        qrexecpolicyArg

" Service Group
hi def link qrexecpolicyServiceGeneric                 qrexecpolicySpecialChar
hi def link qrexecpolicyArgPrefix                      qrexecpolicySpecialChar
hi def link qrexecpolicyArgPrefixGeneric               qrexecpolicyArgPrefix
hi def link qrexecpolicyArgPrefixSpecific              qrexecpolicyArgPrefix
hi def link qrexecpolicySourceGeneric                  qrexecpolicySpecialChar
hi def link qrexecpolicySourceTokenSingle              qrexecpolicyToken
hi def link qrexecpolicySourceTokenComboNormal         qrexecpolicyToken
hi def link qrexecpolicySourceTokenComboType           qrexecpolicyToken
hi def link qrexecpolicySourceUuid                     qrexecpolicyToken
hi def link qrexecpolicyTargetTokenSingle              qrexecpolicyToken
hi def link qrexecpolicyTargetGeneric                  qrexecpolicySpecialChar
hi def link qrexecpolicyTargetTokenComboNormal         qrexecpolicyToken
hi def link qrexecpolicyTargetTokenComboType           qrexecpolicyToken
hi def link qrexecpolicyTargetUuid                     qrexecpolicyToken
hi def link qrexecpolicyResolutionDeny                 qrexecpolicyResolution
hi def link qrexecpolicyResolutionAllow                qrexecpolicyResolution
hi def link qrexecpolicyResolutionAsk                  qrexecpolicyResolution
hi def link qrexecpolicyParamDenyBoolean               qrexecpolicyParam
hi def link qrexecpolicyParamAllowNormal               qrexecpolicyParam
hi def link qrexecpolicyParamAllowTarget               qrexecpolicyParam
hi def link qrexecpolicyParamAllowBoolean              qrexecpolicyParam
hi def link qrexecpolicyParamAllowTargetArgTokenSingle qrexecpolicyToken
hi def link qrexecpolicyParamAllowTargetArgTokenCombo  qrexecpolicyToken
hi def link qrexecpolicyParamAllowTargetArgUuid        qrexecpolicyToken
hi def link qrexecpolicyParamAskBoolean                qrexecpolicyParam
hi def link qrexecpolicyParamAskNormal                 qrexecpolicyParam
hi def link qrexecpolicyParamAskTarget                 qrexecpolicyParam
hi def link qrexecpolicyParamAskTargetArgTokenSingle   qrexecpolicyToken
hi def link qrexecpolicyParamAskTargetArgTokenCombo    qrexecpolicyToken
hi def link qrexecpolicyParamAskTargetArgUuid          qrexecpolicyToken

" Incomplete Group
hi def link qrexecpolicyRuleIncomplete                 qrexecpolicyIncomplete
hi def link qrexecpolicyInclServiceIncomplete          qrexecpolicyIncomplete
hi def link qrexecpolicyInclArgPrefixIncomplete        qrexecpolicyIncomplete
hi def link qrexecpolicyArgPrefixIncomplete            qrexecpolicyIncomplete
hi def link qrexecpolicySourceIncomplete               qrexecpolicyIncomplete
hi def link qrexecpolicyTargetIncomplete               qrexecpolicyIncomplete

" Error Group
hi def link qrexecpolicyMustEndError                   qrexecpolicyError
hi def link qrexecpolicyInclArgPrefixUnknownError      qrexecpolicyError
hi def link qrexecpolicyInclFilePathError              qrexecpolicyError
hi def link qrexecpolicyCharError                      qrexecpolicyError
hi def link qrexecpolicyServiceSpecificError           qrexecpolicyError
hi def link qrexecpolicyServiceGenericError            qrexecpolicyError
hi def link qrexecpolicyArgPrefixUnknownError          qrexecpolicyError
hi def link qrexecpolicyArgPrefixGenericError          qrexecpolicyError
hi def link qrexecpolicyArgPrefixSpecificError         qrexecpolicyError
hi def link qrexecpolicyArgError                       qrexecpolicyError
hi def link qrexecpolicyUuidArgError                   qrexecpolicyError
hi def link qrexecpolicyLiteralError                   qrexecpolicyError
hi def link qrexecpolicyTokenSingleError               qrexecpolicyError
hi def link qrexecpolicyTokenComboError                qrexecpolicyError
hi def link qrexecpolicyTokenComboArgError             qrexecpolicyError
hi def link qrexecpolicyTokenComboTypeArgError         qrexecpolicyError
hi def link qrexecpolicyResolutionUnknownError         qrexecpolicyError
hi def link qrexecpolicyResolutionError                qrexecpolicyError
hi def link qrexecpolicyParamError                     qrexecpolicyError
hi def link qrexecpolicyParamArgError                  qrexecpolicyError
hi def link qrexecpolicyParamBooleanArgError           qrexecpolicyError
hi def link qrexecpolicyParamDenyUnknownError          qrexecpolicyError
hi def link qrexecpolicyParamAllowUnknownError         qrexecpolicyError
hi def link qrexecpolicyParamAskUnknownError           qrexecpolicyError
hi def link qrexecpolicyParamDupUserError              qrexecpolicyError
hi def link qrexecpolicyParamDupNotifyError            qrexecpolicyError
hi def link qrexecpolicyParamDupAutostartError         qrexecpolicyError
hi def link qrexecpolicyParamDupTargetError            qrexecpolicyError
hi def link qrexecpolicyParamDupDefaulttargetError     qrexecpolicyError

" Comment Group
hi def link qrexecpolicyCommentModeline                qrexecpolicyComment

" Reference Group
hi def link qrexecpolicyIncl                           Include
hi def link qrexecpolicyResolution                     Keyword
hi def link qrexecpolicyTodo                           Todo
hi def link qrexecpolicyToken                          Type
hi def link qrexecpolicyParam                          Identifier
hi def link qrexecpolicySpecialChar                    SpecialChar
hi def link qrexecpolicyArg                            String
hi def link qrexecpolicyError                          Error
hi def link qrexecpolicyComment                        Comment
hi def link qrexecpolicyIncomplete                     SpellRare


" Section: End
let b:current_syntax = "qrexecpolicy"

let &cpo = s:cpo_save
unlet s:cpo_save

" vim: sw=2 sts=2 et :
