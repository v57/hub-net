# hub-net local sockets

The agent listens on two kinds of Unix sockets. Neither is reachable from the network.

| Socket | Who uses it | Path |
|---|---|---|
| [Command socket](#command-socket) | The `hub-net` CLI, the Hub app on Linux, any local tool of the agent's user | `<state-dir>/command.sock` (`-socket`) |
| [Service socket](#service-socket) | Services that publish shares (through the hub-service SDKs) and hub-server | `/run/hub-net/agent.sock` on Linux, `/var/run/hub-net/agent.sock` on macOS, for the Hub on this machine; `service.sock` in the membership's directory for a joined Hub |

Both speak JSON over HTTP/1.1 and reject request bodies with unknown fields.

## Command socket

The daemon's control interface: everything the CLI does except `hub-net ports`, which edits the device's port list
file directly so that list never takes input from a socket.

### Access

The socket is `0600`, owned by the agent's user. `-socket-group <group>` makes it `0660` in that group, so a desktop
app run by a group member can send commands too. The socket's directory must let the group through:

```sh
hub-net -socket /run/hub-net/command.sock -socket-group hub-net
```

The Hub app on Linux looks for `/run/hub-net/command.sock`, then `/var/lib/hub-net/command.sock`;
`HUB_NET_COMMAND_SOCKET` names another. The CLI takes the same `-socket` flag, before the command:
`hub-net -socket /run/hub-net/command.sock list`.

### Request

`POST /v1/command` with a JSON body of at most 64 KiB. Commands run one at a time.

```json
{"version": 1, "command": "join", "code": "<invitation>", "own": false}
```

| Field | Type | Used by |
|---|---|---|
| `version` | integer | Always `1`. Another value gets `unsupported command version`. |
| `command` | string | One of the commands below. |
| `code` | string | `join`: the invitation code or `hub://join/` URL. |
| `own` | boolean | `join`: the user says the Hub is theirs (`hub-net join --own`). |
| `address` | string | `local`: hub-server's address. The CLI sends `ws://127.0.0.1:1997` when none is given. |
| `alias` | string | The membership's local name, for `leave`, `pause`, `resume`, `open`, `close`, `vpnAllow`, `vpnRemove`. |
| `port` | integer | `open`, `close`: 1 to 65535. |

| `command` | Effect |
|---|---|
| `join` | Joins the invitation's Hub. Returns `joined`. Can take a while: when the Hub holds the join until an owner approves this device, it waits for that, up to the invitation admission's 10 minutes; the client waits up to 13. Other commands answer meanwhile. |
| `joinStatus` | With the `code` of a join in progress: `approvalCode`, this device's safety code while the Hub waits for an owner's approval, else nothing. The CLI asks every second during a join and prints the code. |
| `local` | Creates the membership for the Hub on this machine. Fails if one exists. Returns `joined.record`. |
| `list` | Returns `items`, paused memberships included. |
| `leave` | Leaves a Hub. Leaving a name that doesn't exist succeeds. |
| `removeAll` | Leaves every Hub. |
| `pause`, `resume` | Stops or restarts a membership's session. Idempotent. |
| `open`, `close` | Publishes or withdraws `127.0.0.1:<port>` as TCP and UDP shares. Idempotent, rolled back on failure. |
| `vpnAllow`, `vpnRemove` | Turns gateway serving on or off for a Hub. |

### Response

```json
{"version": 1, "items": [{"id": "...", "alias": "home", "header": "Home", "status": "connected",
  "nodeUrl": "wss://node.example.com:1964", "gatewayAllowed": false,
  "overlayIpv4": "100.96.0.12", "overlayIpv6": "fd48:5542:4e45::c", "hubAddress": "ws://hub.example.com:1997"}]}
```

| Field | When |
|---|---|
| `version` | Always. |
| `error` | The command failed. The HTTP status is 400. |
| `joined` | `join` and `local`: `record` (the stored membership), `virtualHost` (the Hub's host), `virtualIp` (this device's IPv4 overlay address), and `warning` when the join went through with a caveat, such as no firewall to limit the device's ports. |
| `approvalCode` | `joinStatus`: the code to show, `ddd ddd`. |
| `items` | `list`: one object per membership with `id`, `alias`, `header` (the Hub's display name), `status`, `nodeUrl`, `gatewayAllowed`, `error`, `overlayIpv4`, `overlayIpv6`, `hubAddress`, and `virtualIpv4`/`virtualIpv6` when set. |

`status` is `starting`, `connected`, `disconnected`, `error`, `stopping` or `paused`.

From Go, `management.NewClient(socketPath).Execute(ctx, management.Request{...})` sends a request and turns `error`
into a Go error; [hub-net.md](hub-net.md#go-packages) has an example.

## Service socket

How a local service proves to the agent that a share it publishes points at this device. The hub-service SDKs do this
for you when a service publishes a share; this section is for SDK authors. The SDKs find the socket through
`HUB_NET_AGENT_SOCKET`, else the platform default.

The flow:

1. `POST /challenge` with `{version, type: "challenge", serviceKey, shareName, protocol, target: {host, port}}`. The
   agent returns `{nonce, key, issuedAt, expiresAt}`, where `key` is the agent's key.
2. The service signs the nonce with its Ed25519 service key.
3. `POST /attest` with `{version, type: "attest", serviceKey, shareName, protocol, target, nonce, signature}`. The
   agent checks the nonce is fresh and unused, the signature, and that `target.host` is loopback, then returns a
   signed attestation binding the service key, the agent key, the share name, the protocol and the target. It lasts
   2 minutes; the Hub checks it when the share is registered.
4. The agent adds the attested port to the device's port list for 31 days, so the Hub's grants for it can open.

`GET /status` (or `POST` with `{version, type: "status"}`) returns `{key, ready, reason, serverTime}`.

`POST /binding/proof` is for hub-server: while it handles `hub/net/bind` from the agent on its own machine, it asks
for a proof signed by the agent's key over its connection id and nonce, which shows the agent runs on the same host.

An error is `{"error": {"code": "...", "message": "..."}}`, with codes such as `invalid_request`, `invalid_nonce`,
`invalid_signature` (400), `forbidden`, `remote_target` (403), `agent_unavailable` (503) and `unknown_path` (404).

The socket is `0660`. The Linux package puts it in `/run/hub-net` owned by the `hub-net` user and group; add a
service's user to the `hub-net` group to let it attest. The agent reads the caller's credentials (`SO_PEERCRED` on
Linux, `LOCAL_PEERCRED` on macOS), and access to the socket alone is never proof of a service's identity: the
signature over a fresh nonce is.

The message types live in the `ipc` package (`ChallengeRequest`, `AttestRequest`, `StatusResponse`,
`BindingProofRequest`, ...). The Hub side of attestations and shares is section 10 of the Hub protocol
(`Docs/Devices/protocol.md` in the Hub workspace).
