" Vim completion script
" Language:     Qrexec Policy and Qrexec Policy Service
" Maintainer:   Ben Grande <ben@invisiblethingslab.com>
" License:      Vim (see :h license)
" Repository:   https://github.com/QubesOS/qubes-core-qrexec
" Last Change:  2024 Oct 11


function! qrexeccomplete#Complete(findstart, base)
  " Section: Find the Start
  if a:findstart
    let line = getline('.')
    let start = col('.') - 1
    " The pattern can't be '\k' because some characters aren't add to the
    " 'iskeyword' option as it also affects commands.
    while start > 0 && line[start - 1] =~ '\S\+'
      let start -= 1
    endwhile
    if split(line) !=# []
      let b:compl_directive = split(line)[0]
      let b:compl_context = line[0:start]
    endif
    return start
  endif

  " Section: Default Data
  let res = []
  let files = ""
  let incl_files = ""
  let incl_keys = "!include"
  let keys = incl_keys." !include-dir !include-service !compat-4.0"
  let services = "*"
  let incl_services = services
  let arguments = "* +"
  let incl_arguments = arguments
  let sources = "* uuid: @adminvm @anyvm @dispvm: @dispvm:uuid: @dispvm:@tag:"
  let sources ..= " @type:AdminVM @type:AppVM @type:DispVM @type:StandaloneVM"
  let sources ..= " @type:TemplateVM @tag:"
  let destinations = sources." @default @dispvm"
  let resolutions = "deny allow ask"
  let deny_params = "notify=yes notify=no"
  let allow_params = deny_params." user= autostart=yes autostart=no target="
  let allow_params ..= " target=@adminvm target=@dispvm target=@dispvm:"
  let allow_params ..= " target=uuid: target=@dispvm:uuid:"
  let ask_params = allow_params." default_target= default_target=@adminvm"
  let ask_params ..= " default_target=@dispvm default_target=@dispvm:"
  let ask_params ..= " default_target=uuid: default_target=@dispvm:uuid:"
  let config_keys = "force-user="
  let config_keys ..= " exit-on-client-eof=false exit-on-client-eof=true"
  let config_keys ..= " exit-on-service-eof=false exit-on-service-eof=true"
  let config_keys ..= " wait-for-session=false wait-for-session=true"
  let config_keys ..= " skip-service-descriptor=false"
  let config_keys ..= " skip-service-descriptor=true"

  " Section: Read buffer Data
  " Avoid slow completion by limiting how many lines to read from the buffer.
  let max_line = 1000

  " Discard commented and empty lines.
  " Add previous rules values to list possible completions if the reach the
  " minimum number of fields.
  let file = getline(1, max_line)
  for l in file
    if len(l) == 0
      continue
    endif
    if split(l)[0][0] == "#"
      continue
    endif
    for i in split(l)
      if len(i) != len(matchstr(i, '^[0-9A-Za-z!=_@.*:/+-]\+$'))
        continue
      endif
    endfor
    if split(l)[0] == "!include-service"
      if len(split(l)) < 4
        continue
      endif
      if len(split(l)[1]) == len(matchstr(split(l)[1], '^\([0-9A-Za-z_.-]\+\|*\)$'))
        let incl_services .= " ".split(l)[1]
      endif
      if len(split(l)[2]) == len(matchstr(split(l)[2], '^\(+[0-9A-Za-z_.-]\+\|*\)$'))
        let incl_arguments .= " ".split(l)[2]
      endif
      if len(split(l)[3]) == len(matchstr(split(l)[3], '^[0-9A-Za-z/_.-]\+$'))
        let incl_files .= " ".split(l)[3]
      endif
      continue
    endif
    if split(l)[0][0] == "!"
      continue
    endif
    if &filetype ==# "qrexecconfig"
      continue
    endif
    if &filetype ==# "qrexecpolicyservice"
      if len(split(l)) < 3
        continue
      endif
      if len(split(l)[0]) == len(matchstr(split(l)[0], '^[0-9A-Za-z_-]\+$')) ||
      \  len(split(l)[0]) == len(matchstr(split(l)[0], '^@\(dispvm:\(@tag:\)\?\|tag:\)[0-9A-Za-z_-]\+$')) ||
      \  len(split(l)[0]) == len(matchstr(split(l)[0], '^\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
        let sources .= " ".split(l)[0]
      endif
      if len(split(l)[1]) == len(matchstr(split(l)[1], '^[0-9A-Za-z_-]\+$')) ||
      \  len(split(l)[1]) == len(matchstr(split(l)[1], '^@\(dispvm:\(@tag:\)\?\|tag:\)[0-9A-Za-z_-]\+$')) ||
      \  len(split(l)[1]) == len(matchstr(split(l)[1], '^\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
        let destinations .= " ".split(l)[1]
      endif
      if len(split(l)) < 4
        continue
      endif
      if split(l)[2] ==# "deny"
        continue
      endif
      if split(l)[2] ==# "allow"
        for p in split(l)[3:]
          if len(p) == len(matchstr(p, '^\(user\|target\)=[0-9A-Za-z=_-]\+$')) ||
           \ len(p) == len(matchstr(p, '^target=@dispvm:[0-9A-Za-z=_-]\+$')) ||
           \ len(p) == len(matchstr(p, '^target=\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
            let allow_params .= " ".p
          endif
        endfor
        continue
      elseif split(l)[2] ==# "ask"
        for p in split(l)[3:]
          if len(p) == len(matchstr(p, '^\(user\|\(default_\)\?target\)=[0-9A-Za-z=_-]\+$')) ||
           \ len(p) == len(matchstr(p, '^\(default_\)\?target=@dispvm:[0-9A-Za-z=_-]\+$')) ||
           \ len(p) == len(matchstr(p, '^\(default_\)\?target=\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
          let ask_params .= " ".p
          endif
        endfor
        continue
      endif
    endif
    " qrexecpolicy
    if len(split(l)) < 5
      continue
    endif
    if len(split(l)[0]) == len(matchstr(split(l)[0], '^\([0-9A-Za-z_.-]\+\|*\)$'))
      let services .= " ".split(l)[0]
    endif
    if len(split(l)[1]) == len(matchstr(split(l)[1], '^\(+[0-9A-Za-z_.-]\+\|*\)$'))
      let arguments .= " ".split(l)[1]
    endif
    if len(split(l)[2]) == len(matchstr(split(l)[2], '^[0-9A-Za-z_-]\+$')) ||
    \  len(split(l)[2]) == len(matchstr(split(l)[2], '^@\(dispvm:\(@tag:\)\?\|tag:\)[0-9A-Za-z_-]\+$')) ||
    \  len(split(l)[2]) == len(matchstr(split(l)[2], '^\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
      let sources .= " ".split(l)[2]
    endif
    if len(split(l)[3]) == len(matchstr(split(l)[3], '^[0-9A-Za-z_-]\+$')) ||
    \  len(split(l)[3]) == len(matchstr(split(l)[3], '^@\(dispvm:\(@tag:\)\?\|tag:\)[0-9A-Za-z_-]\+$')) ||
    \  len(split(l)[3]) == len(matchstr(split(l)[3], '^\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
      let destinations .= " ".split(l)[3]
    endif
    if len(split(l)) < 6
      continue
    endif
    if split(l)[4] ==# "deny"
      continue
    endif
    if split(l)[4] ==# "allow"
      for p in split(l)[5:]
        if len(p) == len(matchstr(p, '^\(user\|target\)=[0-9A-Za-z=_-]\+$')) ||
        \  len(p) == len(matchstr(p, '^target=@dispvm:[0-9A-Za-z=_-]\+$')) ||
        \  len(p) == len(matchstr(p, '^target=\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
          let allow_params .= " ".p
        endif
      endfor
      continue
    elseif split(l)[4] ==# "ask"
      for p in split(l)[5:]
        if len(p) == len(matchstr(p, '^\(user\|\(default_\)\?target\)=[0-9A-Za-z=_-]\+$')) ||
        \  len(p) == len(matchstr(p, '^\(default_\)\?target=@dispvm:[0-9A-Za-z=_-]\+$')) ||
        \  len(p) == len(matchstr(p, '^\(default_\)\?target=\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
        let ask_params .= " ".p
        endif
      endfor
      continue
    endif
  endfor

  if exists("b:compl_context")
    let line = getline('.')
    let start = col('.') - 1
    let after = line[start:]
    let line = b:compl_context
    unlet! b:compl_context
  else
    let line = a:base
    let after = ''
  endif

  " Section: 1st field - Config, Policy and Policy Service
  let field_match = matchstr(line, '^\s*\S*$')
  if len(split(line)) == 0 || field_match != ""
    if &filetype ==# "qrexecconfig"
      let cur_items = config_keys
    elseif &filetype ==# "qrexecpolicyservice"
      let cur_items = incl_keys . " " . sources
    else
      let cur_items = services . " " . keys
    endif
    for m in sort(split(cur_items))
      if stridx(m, a:base) == 0
        call add(res, m)
      endif
    endfor
    return res
  endif

  " Section: 2nd field - Config, Directives
  if &filetype ==# "qrexecconfig"
    return ''
  endif
  if split(line)[0] =~ '^!compat-4.0$'
    return ''
  elseif split(line)[0] =~ '^!include$'
    " How to call for file completion?
    return ''
  elseif split(line)[0] =~ '^!include-dir$'
    " How to call for directory completion?
    return ''
  elseif split(line)[0] =~ '^!include-service$'
    " Directive Include Service: 1st field
    let field_match = matchstr(line, '^\s*\S\+\s\+\S*$')
    if field_match != ""
      for m in sort(split(incl_services))
        if stridx(m, a:base) == 0
          call add(res, m)
        endif
      endfor
      return res
    endif
    " Directive Include Service: 2nd field
    let field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S*$')
    if field_match != ""
      if split(line)[1] ==# "*"
        let cur_items = "*"
      else
        let cur_items = incl_arguments
      endif
      for m in sort(split(cur_items))
        if stridx(m, a:base) == 0
          call add(res, m)
        endif
      endfor
      return res
    endif
    " Directive Include Service: 3rd field
    let field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+\S*$')
    if field_match != ""
      for m in sort(split(incl_files))
        if stridx(m, a:base) == 0
          call add(res, m)
        endif
      endfor
      return res
    endif
    return ''
  endif

  " Section: 2nd field - Policy and Policy Service
  let field_match = matchstr(line, '^\s*\S\+\s\+\S*$')
  if field_match != ""
    if split(line)[0] ==# "*"
      let cur_items = "*"
    else
      if &filetype ==# "qrexecpolicyservice"
        let cur_items = destinations
      else
        let cur_items = arguments
      endif
    endif
    for m in sort(split(cur_items))
      if stridx(m, a:base) == 0
        call add(res, m)
      endif
    endfor
    return res
  endif

  " Section: 3rd field - Policy and Policy Service
  let field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S*$')
  if field_match != ""
    if &filetype ==# "qrexecpolicyservice"
      let cur_items = resolutions
    else
      let cur_items = sources
    endif
    for m in sort(split(cur_items))
      if stridx(m, a:base) == 0
        call add(res, m)
      endif
    endfor
    return res
  endif

  " Section: 4th field - Policy and Policy Service
  " This is necessary to make the Policy Service stop matching here by using a
  " '>=' greater than or equal to comparison.
  let field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+\S*$')
  let end_field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+.*$')
  if (&filetype == "qrexecpolicy" && field_match != "") ||
    \(&filetype == "qrexecpolicyservice" && end_field_match != "")
    if &filetype ==# "qrexecpolicyservice"
      if split(line)[2] ==# "deny"
        let cur_items = deny_params
      elseif split(line)[2] ==# "allow"
        let cur_items = allow_params
      elseif split(line)[2] ==# "ask"
        let cur_items = ask_params
      else
        return ''
      endif
    else
      let cur_items = destinations
    endif
    for m in sort(split(cur_items))
      " Use space and tab to check for parameter existence.
      " Whitespace helps differentiate target= from default_target=
      if stridx(line, ' '.split(m, "=")[0].'=') >= 0 ||
       \ stridx(line, '	'.split(m, "=")[0].'=') >= 0
        continue
      endif
      if stridx(m, a:base) == 0
        call add(res, m)
      endif
    endfor
    return res
  endif

  " Section: 5th field - Policy
  let field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+\S\+\s\+\S*$')
  if field_match != ""
    for m in sort(split(resolutions))
      if stridx(m, a:base) == 0
        call add(res, m)
      endif
    endfor
    return res
  endif

  " Section: 6th field - Policy
  let field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+\S\+\s\+\S\+\s\+.*$')
  if field_match != ""
    if split(line)[4] ==# "deny"
      let cur_items = deny_params
    elseif split(line)[4] ==# "allow"
      let cur_items = allow_params
    elseif split(line)[4] ==# "ask"
      let cur_items = ask_params
    else
      return ''
    endif
    for m in sort(split(cur_items))
      " Use space and tab to check for parameter existence.
      " Whitespace helps differentiate target= from default_target=
      if stridx(line, ' '.split(m, "=")[0].'=') >= 0 ||
       \ stridx(line, '	'.split(m, "=")[0].'=') >= 0
        continue
      endif
      if stridx(m, a:base) == 0
        call add(res, m)
      endif
    endfor
    return res
  endif

endfunction

" vim: sw=2 sts=2 et fdm=expr fde=getline(v\:lnum)=~'^\\s*"\ Section\:'?'>1'\:'='
