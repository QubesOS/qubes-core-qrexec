Qubes RPC Command Syntax and Execution
======================================

Qubes RPC Command Syntax
------------------------

Qubes RPC commands targeted at VMs use the following syntax:

    USERNAME:[nogui:]QUBESRPC SERVICE+ARGUMENT SOURCE_DOMAIN

Qubes RPC commands targeted at the host use the following syntax:

    [nogui:]QUBESRPC SERVICE+ARGUMENT SOURCE_DOMAIN REQUESTED_TARGET_TYPE REQUESTED_TARGET

Commands are generally considered trusted.  There is some validation at
various points, but this is haphazard at best.  Instead, it is the job
of the code that constructs a command to ensure that only valid commands
are produced.  For VM -> VM and VM -> dom0 calls, the command is constructed
by qrexec-daemon (for Qubes OS R4.2 and up) or the policy engine (R4.1 and
below).  For dom0 -> VM calls, ensuring correctness is entirely the responsibility
of the code that calls qrexec-client.

qrexec-daemon assumes (but does not check) that:

- The VM name passed on its command line is not empty and does not contain a space.
- For calls to dom0, the requested target from the policy engine is not empty,
  does not contain a space, and is not the literal string ``@``.
- Neither the default username passed on its command line nor the username
  from the policy engine contain a colon.

If any of these assumptions are violated, qrexec-daemon will produce commands
that will not be parsed correctly.  In addition, its serialization of the
request to the policy engine assumes the target VM name on its command line does
not contain a newline.  These are only minor bugs, not security vulnerabilities,
because the inputs -- the policy engine and qubesd -- are ultimately trusted.

Commands sent to a VM are submitted as ``MSG_JUST_EXEC`` or ``MSG_EXEC_CMDLINE``
messages to the VM's ``qrexec-daemon``'s listening socket.  ``qrexec-daemon``
preprocesses these commands before sending them to the VM's ``qrexec-agent``.
This preprocessing checks that the command is NUL-terminated and refuses
the call otherwise.  Furthermore, if the command starts with ``DEFAULT:``,
``DEFAULT`` is replaced with the VM's default username.

The parsing algorithm is the following:

0. The command must contain a trailing NUL byte and have no other NUL characters.
   It is erroneous for the host to submit a command that violates this rule, but
   such violations are not required to be detected.  They result in undefined
   behavior.

1. In VMs only: find the first colon (``:``) in the command.  If there is no colon,
   this is an error.  Set the username to be everything before the colon.  Remove
   the username and colon from the command.

   If the username is the literal string ``DEFAULT``, ``qrexec-daemon`` will replace
   it with its configured default user before transmitting the command to the VM.

2. If the command starts with the literal string ``nogui:``, the command
   is not guaranteed to be able to show a GUI.  The ``nogui:`` prefix is stripped
   before further processing.

   The meaning of this is implementation dependent.  For Linux, it causes
   ``wait-for-session=true`` in the service configuration file to be ignored.
   For Windows, it means that the command is run in session 0 as if it were
   a service, rather than in an interactive desktop session.

   The ``nogui:`` prefix is soft-deprecated.  It will never be included in
   VM -> VM commands, only commands made via ``qvm-run`` from dom0 using
   ``--no-gui``.  Instead, the execution environment of a service should
   be determined by service configuration.  This is possible on Linux,
   but it is not possible on Windows due to `a limitation in the Windows agent`_.
   A proposal to allow specifying ``nogui:`` via qrexec policy `was rejected`_.

   .. _was rejected: https://github.com/QubesOS/qubes-issues/issues/9180
   .. _a limitation in the Windows agent: https://github.com/QubesOS/qubes-issues/issues/9198

3. If the command does not start with the literal string ``QUBESRPC``,
   it is treated as a shell command and further processing is skipped.
   This is mostly a legacy behavior and is only permitted for calls from
   the host.

4. If the next character is not a space (ASCII 0x20), the results are
   undefined.  The Linux agent fails the service call in this case.

5. The ``QUBESRPC`` prefix and subsequent space are stripped.  The rest of the
   command, including the terminating NUL byte, is the *service descriptor*.

6. The service descriptor is split into tokens.  Tokens are separated by a
   single space.  If there are two or more consecutive spaces, or a trailing
   space, the results are undefined.  The Linux agent fails the service call
   if there are two or more consecutive spaces before the second token has been
   parsed.

7. If there are less than two tokens, this is an error and the call fails.
   Executable service (see below) check that there are exactly two or four
   tokens, but socket services do not.

8. The tokens that results are assigned meanings as follows:

   1. The first token has the format ``SERVICE+ARGUMENT``.  The *service name* is
      everything before the first ``+``, or the entire first argument if
      there is no ``+``.  The *service argument* is everything after the first
      ``+``.  If the first argument does not contain ``+``, there is no service
      argument.

   2. The second token is the *source VM name*.

   3. The third token, if present, is the *requested target type*.
      It is ``name`` if the request was to a specific named VM,
      or ``keyword`` if the request was to a keyword.

   4. The fourth token, if present, is the *requested target*.
      It is the target requested by the VM normalized by the policy engine.
      For instance, nonexistent VM names have been replaced by ``@default``.
      If this starts with an ``@``, it is removed and the third token is
      ``keyword``.

      Allowed keywords in this context are:

      - ``adminvm``: the Administrative VM, dom0.
      - ``default``: Default VM, lets qrexec policy choose.
      - ``dispvm``: Freshly created disposable VM based on source VM's default Disposable VM template.
      - ``dispvm:VMNAME``: Freshly create disposable VM based on the specified VM.

      Device model stubdomains (which have names ending in ``-dm``) *are* valid
      targets for qrexec requests, but *only* if they have a qrexec daemon running,
      and *only* if the call is made from dom0.  The policy engine, and therefore
      all VM-initiated requests, act as if stubdomains do not exist.

   Tokens 3 and 4 are *always* present for calls to the host and *never* present otherwise.
   This is not checked, though.

The use of a command string for calls to the host is an implementation detail.
A future implementation of qrexec might avoid creating the command string at all,
as it serves no function other than as an intermediate representation.  After
v4.2.19, it does not even leave the ``qrexec-daemon`` process.  In the future,
an array of strings should be used instead.

Qubes RPC Call Flow
-------------------

In R4.1, the qrexec policy engine invokes ``qrexec-client``, which submits
the command to a ``qrexec-daemon`` for execution or runs it on the host.  In R4.2 before
v4.2.19, ``qrexec-daemon`` uses the result of the policy evaluation to call ``qrexec-client``
itself.  In v4.2.19 and above, ``qrexec-daemon`` directly submits or executes the call,
and ``qrexec-client`` is only used for calls submitted by dom0.

Qubes RPC service execution
---------------------------

A Qubes RPC service is a file, socket, or symbolic link under ``/etc/qubes-rpc/``
or ``/usr/local/etc/qubes-rpc``.  When a call is made, ``qrexec-agent`` (in a VM)
or ``qrexec-client`` (in dom0) searches for the first entry in the following list:

1. ``/usr/local/etc/qubes-rpc/SERVICE+ARG``
2. ``/etc/qubes-rpc/SERVICE+ARG``
3. ``/usr/local/etc/qubes-rpc/SERVICE``
4. ``/etc/qubes-rpc/SERVICE``

``SERVICE`` is replaced by the service being invoked, and ``ARG`` by its argument.
If ``SERVICE`` is longer than ``NAME_MAX`` (255 on Linux), the call fails.  If
``SERVICE`` is ``NAME_MAX`` or less, but ``SERVICE+ARG`` exceeds ``NAME_MAX``,
steps 1 and 3 are skipped.  If no argument at all is provided, the search proceeds
as if an empty argument is passed.  This is only possible for calls made by dom0,
as VM => VM calls insert an empty argument if no argument is provided.

The search is terminated by any of the following:

1. There are no more paths to check.  This causes the search to fail.
2. ``lstat(2)`` fails, setting errno to a value other than ``ENOENT``.
   This causes the search to fail.
3. ``lstat(2)`` succeeds.  The search concludes successfully.

If a command is not found, qrexec pretends that it exited with status 127.
If a command cannot be executed, qrexec pretends that it exited with status 125.
In both cases, no data is read from stdin, and no data is written to stdout or
stderr.  However, the actual cause of the failure is logged within the VM.

Symbolic links are followed when executing a service.  However, it is usually
a mistake to use program as a qrexec service that was not intended for this use,
such as ``/usr/bin/cat``.  This is because ``-`` is allowed to be the first
character in the service argument, allowing option injection attacks.
Instead, a wrapper script should be used.

Types of qrexec services
------------------------

There are three different types of qrexec services.  The distinction
between service types is mostly invisible to callers.

1. Executable services.  These are files with execute permission, as
   reported by ``euidaccess(2)``.  They are executed using ``execve()``.
   In a VM (but not in dom0), they are executed in a proper login session.
   On Linux, PAM is used.

   By default, these will run as the user passed by dom0.  This can be overridden
   with ``force-user=`` in the configuration file.  The username must be a string
   user due to PAM limitations.

   If a non-empty string is passed as the service argument, it is passed as the
   first argument to the service.  The service environment is modified as follows:

   1. All environment variables with names starting with ``QREXEC`` are stripped.
   2. ``QREXEC_REMOTE_DOMAIN`` is set to the name of the calling VM.
   3. ``QREXEC_SERVICE_FULL_NAME`` is set to the full name of the service,
      including the argument if any.
   4. If the service *is not* running in dom0, ``QREXEC_REQUESTED_TARGET_TYPE`` is
      set to an empty value.
   5. If the service *is* running in dom0, and the requested target starts with ``@``,
      ``QREXEC_REQUESTED_TARGET_TYPE`` is set to ``keyword`` and
      ``QREXEC_REQUESTED_TARGET_KEYWORD`` is set to the requested target with the
      leading ``@`` removed.
   6. If the service *is* running in dom0, and the requested target *does not* start with ``@``,
      ``QREXEC_REQUESTED_TARGET_TYPE`` is set to ``name`` and
      ``QREXEC_REQUESTED_TARGET`` is set to the requested target.

2. Socket-based services.  These are ``AF_UNIX`` stream sockets on the filesystem.
   Data passed via stdin will be written to the socket, and data from the socket will
   will be written to stdout.

   By default, qrexec will write the service descriptor before it writes any data
   from the peer.  This can be disabled with ``skip-service-descriptor=true``
   in the configuration file.  The username is *not* sent to the socket.

   The connection to the service is always made as *root* or as the *default user*.
   Which one is used is unspecified, and services should not rely on this.  Instead,
   the socket should be owned by ``root:qubes`` with ``0660`` permissions.

3. Symlinks to ``/dev/tcp/``, optionally followed by a hostname and a port number.
   The allowed formats of the symlink target are::

       /dev/tcp/HOST/PORT
       /dev/tcp/HOST
       /dev/tcp

   The first syntax ignores the service argument.  The second syntax
   treats the entire service argument as the port, and the third syntax
   splits the service argument (on the last ``+``) to obtain both the host
   and the port.

   The port must be a decimal integer with no leading zeros.  This is checked:
   the call will fail if it is not.

   The host may be either an IPv4 or IPv6 address.  If it contains ``:`` or ``%``, it
   is checked to be an IPv6 address by setting :code:`.ai_family = AF_INET6`.
   Otherwise, it may be either an IPv4 or IPv6 address.  In a service call
   argument, ``:`` must be encoded as ``+`` and ``%`` is not allowed.  ``AI_NUMERICHOST``
   is always set, so hostnames are not allowed.

   TCP socket services are checked for before executable or socket-based services, so
   a symlink to a service under ``/dev/tcp/`` will be interpreted as a TCP socket service.
   This is not expected to be an issue in practice, because ``/dev/tcp/`` does not exist
   on any common \*nix variant.

   Service descriptors are still sent to TCP socket services by default.  If a TCP socket
   service is used for a service that is not Qubes OS-aware, ``skip-service-descriptor = true``
   should be used in the configuration file.
