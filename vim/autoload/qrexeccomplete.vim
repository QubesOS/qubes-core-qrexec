vim9script noclear

# Vim completion script
# Language:     Qrexec Policy and Qrexec Policy Service
# Maintainer:   Ben Grande <ben@invisiblethingslab.com>
# License:      Vim (see :h license)
# Repository:   https://github.com/QubesOS/qubes-core-qrexec
# Last Change:  2026 Mar 02

export def Complete(findstart: bool, base: string): any
  # Section: Find the Start
  var line: string
  var start: number
  if findstart
    line = getline('.')
    start = col('.') - 1
    # The pattern can't be '\k' because some characters aren't add to the
    # 'iskeyword' option as it also affects commands.
    while start > 0 && line[start - 1] =~ '\S\+'
      --start
    endwhile
    if split(line) !=# []
      b:compl_directive = split(line)[0]
      b:compl_context = line[0 : start]
    endif
    echomsg start
    return start
  endif

  # Section: Default Data
  var res: list<string> = []
  var files: string = ""
  var incl_files: string = ""
  var incl_keys: string = "!include"
  var keys: string = incl_keys .. " !include-dir !include-service !compat-4.0"
  var services: string = "*"
  var incl_services: string = services
  var arguments: string = "* +"
  var incl_arguments: string = arguments
  var sources: string = "* uuid: @adminvm @anyvm @dispvm: @dispvm:uuid: @dispvm:@tag:"
  sources ..= " @type:AdminVM @type:AppVM @type:DispVM @type:StandaloneVM"
  sources ..= " @type:TemplateVM @tag:"
  var destinations: string = sources .. " @default @dispvm"
  var resolutions: string = "deny allow ask"
  var deny_params: string = "notify=yes notify=no"
  var allow_params: string = deny_params .. " user= autostart=yes autostart=no target="
  allow_params ..= " target=@adminvm target=@dispvm target=@dispvm:"
  allow_params ..= " target=uuid: target=@dispvm:uuid:"
  var ask_params: string = allow_params .. " default_target= default_target=@adminvm"
  ask_params ..= " default_target=@dispvm default_target=@dispvm:"
  ask_params ..= " default_target=uuid: default_target=@dispvm:uuid:"
  var config_keys: string = "force-user="
  config_keys ..= " exit-on-client-eof=false exit-on-client-eof=true"
  config_keys ..= " exit-on-service-eof=false exit-on-service-eof=true"
  config_keys ..= " wait-for-session=false wait-for-session=true"
  config_keys ..= " skip-service-descriptor=false"
  config_keys ..= " skip-service-descriptor=true"

  # Section: Read buffer Data
  # Avoid slow completion by limiting how many lines to read from the buffer.
  const MAX_LINE: number = 1000

  # Discard commented and empty lines.
  # Add previous rules values to list possible completions if the reach the
  # minimum number of fields.
  var file: list<string> = getline(1, MAX_LINE)
  var fields: list<string>
  for l in file
    if len(l) == 0
      continue
    endif
    fields = split(l)
    if fields[0][0] == "#"
      continue
    endif
    for i in fields
      if len(i) != len(matchstr(i, '^[0-9A-Za-z!=_@.*:/+-]\+$'))
        continue
      endif
    endfor
    if fields[0] == "!include-service"
      if len(fields) < 4
        continue
      endif
      if len(fields[1]) == len(matchstr(fields[1], '^\([0-9A-Za-z_.-]\+\|*\)$'))
        incl_services ..= " " .. fields[1]
      endif
      if len(fields[2]) == len(matchstr(fields[2], '^\(+[0-9A-Za-z_.-]\+\|*\)$'))
        incl_arguments ..= " " .. fields[2]
      endif
      if len(fields[3]) == len(matchstr(fields[3], '^[0-9A-Za-z/_.-]\+$'))
        incl_files ..= " " .. fields[3]
      endif
      continue
    endif
    if fields[0][0] == "!"
      continue
    endif
    if &filetype ==# "qrexecconfig"
      continue
    endif
    if &filetype ==# "qrexecpolicyservice"
      if len(fields) < 3
        continue
      endif
      if len(fields[0]) == len(matchstr(fields[0], '^[0-9A-Za-z_-]\+$')) ||
      \  len(fields[0]) == len(matchstr(fields[0], '^@\(dispvm:\(@tag:\)\?\|tag:\)[0-9A-Za-z_-]\+$')) ||
      \  len(fields[0]) == len(matchstr(fields[0], '^\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
        sources ..= " " .. fields[0]
      endif
      if len(fields[1]) == len(matchstr(fields[1], '^[0-9A-Za-z_-]\+$')) ||
      \  len(fields[1]) == len(matchstr(fields[1], '^@\(dispvm:\(@tag:\)\?\|tag:\)[0-9A-Za-z_-]\+$')) ||
      \  len(fields[1]) == len(matchstr(fields[1], '^\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
        destinations ..= " " .. fields[1]
      endif
      if len(fields) < 4
        continue
      endif
      if fields[2] ==# "deny"
        continue
      endif
      if fields[2] ==# "allow"
        for p in fields[3 : ]
          if len(p) == len(matchstr(p, '^\(user\|target\)=[0-9A-Za-z=_-]\+$')) ||
           \ len(p) == len(matchstr(p, '^target=@dispvm:[0-9A-Za-z=_-]\+$')) ||
           \ len(p) == len(matchstr(p, '^target=\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
            allow_params ..= " " .. p
          endif
        endfor
        continue
      elseif fields[2] ==# "ask"
        for p in fields[3 : ]
          if len(p) == len(matchstr(p, '^\(user\|\(default_\)\?target\)=[0-9A-Za-z=_-]\+$')) ||
           \ len(p) == len(matchstr(p, '^\(default_\)\?target=@dispvm:[0-9A-Za-z=_-]\+$')) ||
           \ len(p) == len(matchstr(p, '^\(default_\)\?target=\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
          ask_params ..= " " .. p
          endif
        endfor
        continue
      endif
    endif
    # qrexecpolicy
    if len(fields) < 5
      continue
    endif
    if len(fields[0]) == len(matchstr(fields[0], '^\([0-9A-Za-z_.-]\+\|*\)$'))
      services ..= " " .. fields[0]
    endif
    if len(fields[1]) == len(matchstr(fields[1], '^\(+[0-9A-Za-z_.-]\+\|*\)$'))
      arguments ..= " " .. fields[1]
    endif
    if len(fields[2]) == len(matchstr(fields[2], '^[0-9A-Za-z_-]\+$')) ||
    \  len(fields[2]) == len(matchstr(fields[2], '^@\(dispvm:\(@tag:\)\?\|tag:\)[0-9A-Za-z_-]\+$')) ||
    \  len(fields[2]) == len(matchstr(fields[2], '^\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
      sources ..= " " .. fields[2]
    endif
    if len(fields[3]) == len(matchstr(fields[3], '^[0-9A-Za-z_-]\+$')) ||
    \  len(fields[3]) == len(matchstr(fields[3], '^@\(dispvm:\(@tag:\)\?\|tag:\)[0-9A-Za-z_-]\+$')) ||
    \  len(fields[3]) == len(matchstr(fields[3], '^\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
      destinations ..= " " .. fields[3]
    endif
    if len(fields) < 6
      continue
    endif
    if fields[4] ==# "deny"
      continue
    endif
    if fields[4] ==# "allow"
      for p in fields[5 : ]
        if len(p) == len(matchstr(p, '^\(user\|target\)=[0-9A-Za-z=_-]\+$')) ||
        \  len(p) == len(matchstr(p, '^target=@dispvm:[0-9A-Za-z=_-]\+$')) ||
        \  len(p) == len(matchstr(p, '^target=\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
          allow_params ..= " " .. p
        endif
      endfor
      continue
    elseif fields[4] ==# "ask"
      for p in fields[5 : ]
        if len(p) == len(matchstr(p, '^\(user\|\(default_\)\?target\)=[0-9A-Za-z=_-]\+$')) ||
        \  len(p) == len(matchstr(p, '^\(default_\)\?target=@dispvm:[0-9A-Za-z=_-]\+$')) ||
        \  len(p) == len(matchstr(p, '^\(default_\)\?target=\(@dispvm:\)\?uuid:[0-9a-f]\{8}\(-[0-9a-f]\{4}\)\{3}-[0-9a-f]\{12}$'))
        ask_params ..= " " .. p
        endif
      endfor
      continue
    endif
  endfor

  var after: string
  if exists("b:compl_context")
    line = getline('.')
    start = col('.') - 1
    after = line[start : ]
    line = b:compl_context
    unlet! b:compl_context
  else
    line = base
    after = ''
  endif

  var field_match: string
  var cur_items: string
  # Section: 1st field - Config, Policy and Policy Service
  field_match = matchstr(line, '^\s*\S*$')
  if len(split(line)) == 0 || field_match != ""
    if &filetype ==# "qrexecconfig"
      cur_items = config_keys
    elseif &filetype ==# "qrexecpolicyservice"
      cur_items = incl_keys .. " " .. sources
    else
      cur_items = services .. " " .. keys
    endif
    for m in sort(split(cur_items))
      if stridx(m, base) == 0
        res->add(m)
      endif
    endfor
    return res
  endif

  # Section: 2nd field - Config, Directives
  if &filetype ==# "qrexecconfig"
    return ''
  endif
  if split(line)[0] =~ '^!compat-4.0$'
    return ''
  elseif split(line)[0] =~ '^!include$'
    # How to call for file completion?
    return ''
  elseif split(line)[0] =~ '^!include-dir$'
    # How to call for directory completion?
    return ''
  elseif split(line)[0] =~ '^!include-service$'
    # Directive Include Service: 1st field
    field_match = matchstr(line, '^\s*\S\+\s\+\S*$')
    if field_match != ""
      for m in sort(split(incl_services))
        if stridx(m, base) == 0
          res->add(m)
        endif
      endfor
      return res
    endif
    # Directive Include Service: 2nd field
    field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S*$')
    if field_match != ""
      if split(line)[1] ==# "*"
        cur_items = "*"
      else
        cur_items = incl_arguments
      endif
      for m in sort(split(cur_items))
        if stridx(m, base) == 0
          res->add(m)
        endif
      endfor
      return res
    endif
    # Directive Include Service: 3rd field
    field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+\S*$')
    if field_match != ""
      for m in sort(split(incl_files))
        if stridx(m, base) == 0
          res->add(m)
        endif
      endfor
      return res
    endif
    return ''
  endif

  # Section: 2nd field - Policy and Policy Service
  field_match = matchstr(line, '^\s*\S\+\s\+\S*$')
  if field_match != ""
    if split(line)[0] ==# "*"
      cur_items = "*"
    else
      if &filetype ==# "qrexecpolicyservice"
        cur_items = destinations
      else
        cur_items = arguments
      endif
    endif
    for m in sort(split(cur_items))
      if stridx(m, base) == 0
        res->add(m)
      endif
    endfor
    return res
  endif

  # Section: 3rd field - Policy and Policy Service
  field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S*$')
  if field_match != ""
    if &filetype ==# "qrexecpolicyservice"
      cur_items = resolutions
    else
      cur_items = sources
    endif
    for m in sort(split(cur_items))
      if stridx(m, base) == 0
        res->add(m)
      endif
    endfor
    return res
  endif

  # Section: 4th field - Policy and Policy Service
  # This is necessary to make the Policy Service stop matching here by using a
  # '>=' greater than or equal to comparison.
  field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+\S*$')
  var end_field_match: string
  end_field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+.*$')
  if (&filetype == "qrexecpolicy" && field_match != "") ||
    \ (&filetype == "qrexecpolicyservice" && end_field_match != "")
    if &filetype ==# "qrexecpolicyservice"
      if split(line)[2] ==# "deny"
        cur_items = deny_params
      elseif split(line)[2] ==# "allow"
        cur_items = allow_params
      elseif split(line)[2] ==# "ask"
        cur_items = ask_params
      else
        return ''
      endif
    else
      cur_items = destinations
    endif
    for m in sort(split(cur_items))
      # Use space and tab to check for parameter existence.
      # Whitespace helps differentiate target= from default_target=
      if stridx(line, ' ' .. split(m, "=")[0] .. '=') >= 0 ||
       \ stridx(line, '	' .. split(m, "=")[0] .. '=') >= 0
        continue
      endif
      if stridx(m, base) == 0
        res->add(m)
      endif
    endfor
    return res
  endif

  # Section: 5th field - Policy
  field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+\S\+\s\+\S*$')
  if field_match != ""
    for m in sort(split(resolutions))
      if stridx(m, base) == 0
        res->add(m)
      endif
    endfor
    return res
  endif

  # Section: 6th field - Policy
  field_match = matchstr(line, '^\s*\S\+\s\+\S\+\s\+\S\+\s\+\S\+\s\+\S\+\s\+.*$')
  if field_match != ""
    if split(line)[4] ==# "deny"
      cur_items = deny_params
    elseif split(line)[4] ==# "allow"
      cur_items = allow_params
    elseif split(line)[4] ==# "ask"
      cur_items = ask_params
    else
      return ''
    endif
    for m in sort(split(cur_items))
      # Use space and tab to check for parameter existence.
      # Whitespace helps differentiate target= from default_target=
      if stridx(line, ' ' .. split(m, "=")[0] .. '=') >= 0 ||
       \ stridx(line, '	' .. split(m, "=")[0] .. '=') >= 0
        continue
      endif
      if stridx(m, base) == 0
        res->add(m)
      endif
    endfor
    return res
  endif
  return ''

enddef

# vim: sw=2 sts=2 et fdm=expr fde=getline(v\:lnum)=~'^\\s*#\ Section\:'?'>1'\:'='
