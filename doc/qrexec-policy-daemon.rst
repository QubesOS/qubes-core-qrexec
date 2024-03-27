Qubes Policy Request Daemon
===========================

Protocol
^^^^^^^^

Request
-------

Newline-separated:

- domain_id=
- source=
- intended_target=
- service_and_arg=
- process_ident=

Optional arguments:

- assume_yes_for_ask=yes
- just_evaluate=yes


Response
--------

`result=allow/deny`

Any possible extensions may be placed on next lines.
All responses that do not start with `result=allow` or `result=deny` are
incorrect and will be rejected.

End of request is always an empty line.
Response is always terminated by EOF.

Extensions include:

- `target=`: Name of the target, optionally preceded by `@dispvm:`
  `@dispvm:` prefix means that this is a disposable VM template and a new disposable VM will be created automatically.
  In allow responses, ignored if `target_uuid=` is present, required otherwise.
  Forbidden in deny responses.
- `autostart=`: `True` to automatically start the VM, `False` to not start it.
  Anything else is invalid.
  Required in allow responses, forbidden in deny responses.
- `requested_target=`: Normalized version of the target domain.
