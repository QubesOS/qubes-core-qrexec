" Vim syntax file
" Language:	qrexec policy file
" Maintainer:	Wojtek Porczyk <woju@invisiblethingslab.com>
" Last Change:	2019 Mar 07

" quit when a syntax file was already loaded
if exists("b:current_syntax")
    finish
endif

" !, -, ., 0-9, A-Z, a-z
setlocal iskeyword=33,45-46,48-57,65-90,97-122

syn keyword qubespolicyInclude
    \ !include !include-dir !include-service !compat-4.0

syn keyword qubespolicyResolution
    \ allow deny ask

syn keyword qubespolicyTodo
    \ TODO NOTE XXX

syn match qubespolicyParam      '\<\S*=\@='
syn match qubespolicyVMTokenA   '\s@\(adminvm\|anyvm\|default\|dispvm\)\>'
syn match qubespolicyVMTokenB   '\s@\(type:\|tag:\|dispvm:\(@tag:\)\?\)'

syn match qubespolicyArgprefix  '\s\@<=[*+]'
syn match qubespolicyArgument   '\s\@<=[*+]\S*' contains=qubespolicyArgprefix

syn match qubespolicyError      '\$\S*\|,'
syn match qubespolicyComment    '^#.*$' contains=qubespolicyTodo

hi def link qubespolicyVMTokenA     qubespolicyVMToken
hi def link qubespolicyVMTokenB     qubespolicyVMToken

hi def link qubespolicyInclude      Include
hi def link qubespolicyResolution   Keyword
hi def link qubespolicyTodo         Todo
hi def link qubespolicyVMToken      Type
hi def link qubespolicyParam        Identifier
hi def link qubespolicyArgprefix    SpecialChar
hi def link qubespolicyArgument     String
hi def link qubespolicyError        Error
hi def link qubespolicyComment      Comment
