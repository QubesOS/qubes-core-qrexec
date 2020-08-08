# `qrexec-policy-agent`

## Protocol

The policy agent works as a socket-based service. It handles the following Qubes RPC calls:

### `policy.Ask`

Display a prompt about whether to allow an action.

The request is a JSON dictionary with the following keys:
- `source` - source domain (`"work"`)
- `service` - name of service without argument (`"qubes.Filecopy"`)
- `argument` - argument, always starts with `+` (`"+arg"`, `"+"` if empty)
- `targets` - list of possible targets (`["personal", "@dispvm:work"]`)
- `default_target` - initially chosen target (`"personal"`) or empty string (`""`)
- `icons` - a dictionary icon names (recognizable by GTK) for all domains mentioned in other keys (`{"personal": "red", "work": "green", ...}`)

The response is plain ASCII. It's either `allow:` followed by a chosen target (`allow:personal`) or `deny`.

### `policy.Notify`

Display a notification regarding an action.

The request is a JSON dictionary with the following keys:

- `resolution` - one of:
  - "allow" - the service was allowed to run
  - "deny" - the service was denied
  - "fail" - the service was allowed, but failed to start
- `source` - source domain ("work")
- `service` - name of service without argument (`"qubes.Filecopy"`)
- `argument` - argument, always starts with `+` (`"+arg"`, `"+"` if empty)
- `target` - target, either intended (in case of `"deny"`) or actual (otherwise)

The response is empty.
