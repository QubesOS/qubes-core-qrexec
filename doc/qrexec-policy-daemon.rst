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

If ``/run/qubes/qrexec-log-timing`` exists in dom0, qrexec-daemon and the
policy daemon log how long each stage of every call from a qube took. Creating
or removing the file takes effect immediately, and the file is removed at
reboot. Calls started from dom0 (e.g. ``qvm-run``) are not logged.

For example, to profile ``qvm-ls`` run in the qube ``work`` (which needs
read-only Admin API access for that):

1. In dom0, turn timing on::

       touch /run/qubes/qrexec-log-timing

2. In ``work``, run the command::

       qvm-ls

3. In dom0, read the timing of each call. qrexec-daemon logs one line per call
   to the log of the calling qube::

       $ grep timing /var/log/qubes/qrexec.work.log
       ... qrexec: admin.vm.property.GetAll: work -> debian-13-xfce: timing: policy=1.9ms connect_source=0.4ms start_service=0.1ms data_vchan=2.8ms service=5.4ms total=10.6ms
       ... qrexec: admin.vm.property.GetAll: work -> default-dvm: timing: policy=1.9ms connect_source=0.4ms start_service=0.1ms data_vchan=4.0ms service=7.2ms total=13.6ms
       ...

   ``policy`` is the time to get the policy decision. The policy daemon logs
   its own breakdown of it::

       $ journalctl -o cat -u qubes-qrexec-policy-daemon | grep timing
       qrexec: admin.vm.property.GetAll: work -> debian-13-xfce: timing: system_info=0.9ms load_policy=0.0ms evaluate=0.1ms execute=0.3ms total=1.3ms
       qrexec: admin.vm.property.GetAll: work -> default-dvm: timing: system_info=0.9ms load_policy=0.0ms evaluate=0.1ms execute=0.2ms total=1.2ms
       ...

4. In dom0, turn timing off::

       rm /run/qubes/qrexec-log-timing

The qrexec-daemon stages are:

- ``policy``: getting the policy decision. For ``ask``, this includes the time
  the user takes to answer.
- ``create_dispvm``, ``start_vm``: creating the target disposable, starting
  the target qube, if needed.
- ``exec_target``: asking the target qube to start the service.
- ``connect_source``: telling the calling qube where to connect.
- ``start_service``: starting the service in dom0.
- ``data_vchan``: setting up the data connection with the calling qube.
- ``service``: the time the service ran, for calls to dom0 and to disposables.
  For calls to other qubes, the line ends when the connection is set up.
- ``kill``: killing the disposable.

Admin API calls (``admin.*``) run in dom0, whatever qube they name.

The policy daemon stages are:

- ``system_info``: getting the qubes and their properties from qubesd.
- ``load_policy``: loading the policy files (the policy daemon only does it
  when they changed).
- ``evaluate``: finding the matching rule.
- ``execute``: acting on it. For ``ask``, this includes the time the user
  takes to answer.
- ``notify``: notifying the user that the call was denied.

When a call is denied, the line stops at the stage that denied it.
