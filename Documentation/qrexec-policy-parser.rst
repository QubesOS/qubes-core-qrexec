:py:mod:`qrexec.policy.parser` -- Qubes RPC policy parser
=========================================================

.. module:: qrexec.policy.parser

Qrexec policy format is available as separate specification:
:doc:`multifile-policy`.

Representing domain names
-------------------------

.. autoclass:: VMToken
   :members:

.. autoclass:: Source
   :members:
.. autoclass:: Target
   :members:
.. autoclass:: Redirect
   :members:
.. autoclass:: IntendedTarget
   :members:

The classes should be instantiated using either :class:`VMToken` or the context
that expects the token.

>>> type(VMToken('@adminvm'))
<class 'qrexec.policy.parser.AdminVM'>
>>> type(Target('@adminvm'))
<class 'qrexec.policy.parser.AdminVM'>

The latter has the advantage that tokens inappropriate for the context are
rejected:

>>> Redirect('@tag:tag1')
Traceback (most recent call last):
...
qrexec.exc.PolicySyntaxError: <unknown>:None: invalid redirect token: '@tag:tag1'

The tokens are as follows. EXACT means the token should match exactly. PREFIX
means anything goes after the prefix. When two different prefixes match
(``'@dispvm:'``/``'@dispvm:@tag:'``), the longer one is chosen.

.. autoclass:: AdminVM
   :show-inheritance:

   .. autoattribute:: EXACT

.. autoclass:: AnyVM
   :show-inheritance:

   .. autoattribute:: EXACT

.. autoclass:: DefaultVM
   :show-inheritance:

   .. autoattribute:: EXACT

.. autoclass:: TypeVM
   :show-inheritance:

   .. autoattribute:: PREFIX

.. autoclass:: TagVM
   :show-inheritance:

   .. autoattribute:: PREFIX

.. autoclass:: DispVM
   :show-inheritance:
   :members: get_dispvm_template

   .. autoattribute:: EXACT

.. autoclass:: DispVMTemplate
   :show-inheritance:

   .. autoattribute:: PREFIX

.. autoclass:: DispVMTag
   :show-inheritance:

   .. autoattribute:: PREFIX

There is a helper metaclass for this, do not use it elsewhere:

.. autoclass:: VMTokenMeta


Request object
--------------

.. autoclass:: Request
   :members:
   :member-order: bysource

Actions and resolutions
-----------------------

There are two things that represent "what to do" when there is a match in
policy: actions and resolutions. Action is part of a :class:`Rule`, it means
what this rule prescripts. In contrast, a resolution is something that happens
after a :class:`Rule` was actually matched to :class:`Request`.

.. autoclass:: ActionType
   :members:
.. autoclass:: Allow
   :members:
.. autoclass:: Deny
   :members:
.. autoclass:: Ask
   :members:

.. autoclass:: Action
   :show-inheritance:

.. autoclass:: AbstractResolution
   :members:
.. autoclass:: AllowResolution
   :members:
.. autoclass:: AskResolution
   :members:

Parsers
-------

.. autoclass:: Rule
   :members:
   :member-order: bysource

.. autoclass:: AbstractParser
   :members:
   :member-order: bysource

.. autoclass:: AbstractPolicy
   :members:
   :member-order: bysource

.. autoclass:: AbstractFileLoader
   :members:
   :member-order: bysource

.. autoclass:: AbstractDirectoryLoader
   :members:
   :member-order: bysource

.. autoclass:: AbstractFileSystemLoader
   :members:
   :member-order: bysource

.. autoclass:: FilePolicy
   :members:
   :member-order: bysource

Miscellaneous and test facilities
---------------------------------

.. .. autoclass:: ValidateIncludesParser
   :members:
   :member-order: bysource

.. .. autoclass:: CheckIfNotIncludedParser
   :members:
   :member-order: bysource

.. autoclass:: TestLoader
   :members:
   :member-order: bysource

.. autoclass:: TestPolicy
   :members:
   :member-order: bysource

Helper functions
----------------

.. autofunction:: get_invalid_characters
.. autofunction:: parse_service_and_argument
.. autofunction:: validate_service_and_argument
.. autofunction:: filter_filepaths
.. .. autofunction:: toposort
