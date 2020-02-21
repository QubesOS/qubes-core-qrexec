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

End of response and request is always an empty line.