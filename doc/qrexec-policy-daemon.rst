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
- requested_source=

End of request is always an empty line.

Response
--------

result=allow/deny

All responses that do not start with result=allow or result=deny are incorrect and will be rejected.
Any possible extensions may be placed on next lines.
Response is always terminated by EOF.

- result=allow requires autostart= and either target= or target_uuid= extensions.
- result=deny forbids autostart=, target= and target_uuid= extensions.

Extensions include:

- target=: The name of the target qube. If prefixed with @dispvm:, it indicates a disposable VM template, and a new disposable VM will be created automatically.
- target_uuid=: The UUID of the target qube.
- autostart=: True to automatically start the VM, False to not start it. Anything else is invalid.
- requested_target=: Normalized version of the target qube.
- service=: Service and argument to be used.
- policy_source=: The name of the source qube. This is the processed `SOURCE_QUBE` argument from `qrexec-client-vm` by policies.
