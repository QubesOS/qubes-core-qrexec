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

Timing
^^^^^^

If ``/run/qubes/qrexec-log-timing`` exists in dom0, the policy daemon logs how
long each stage of every policy request took::

    $ journalctl -o cat -u qubes-qrexec-policy-daemon | grep timing
    qrexec: admin.vm.property.GetAll: work -> debian-13-xfce: timing: system_info=0.9ms load_policy=0.0ms evaluate=0.1ms execute=0.3ms total=1.3ms

To enable it, run ``touch /run/qubes/qrexec-log-timing`` in dom0. Remove the
file to disable it. Both take effect immediately, and the file is removed at
reboot.

The stages are:

- ``system_info``: getting the qubes and their properties from qubesd.
- ``load_policy``: loading the policy files (the policy daemon only does it
  when they changed).
- ``evaluate``: finding the matching rule.
- ``execute``: acting on it. For ``ask``, this includes the time the user
  takes to answer.
- ``notify``: notifying the user that the call was denied.

When a call is denied, the line stops at the stage that denied it.
