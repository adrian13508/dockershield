# Design: hosted probe

Status: design only. Nothing in this document is built.

## Problem

`dockershield probe` needs a second machine. Someone with one VPS and a laptop behind
the same provider firewall rules, or with no second machine at all, cannot get an
outside view. A hosted endpoint can provide it.

## The one rule

**The service probes only the IP address the request came from.** There is no parameter
for a target host. A server asks "what can you reach on me?" and nothing else can be
asked. This removes the main abuse case of any hosted scanner: pointing it at someone
else.

Consequences:

- The request must come from the server being checked, so the client is `dockershield`
  running there (`dockershield probe --hosted`), not a web form.
- The target is the TCP peer address of the request. `X-Forwarded-For` and similar
  headers are ignored unless set by the service's own load balancer, and then only the
  entry added by that load balancer is used.
- A server behind NAT gets its NAT gateway probed. That is the correct outside view,
  but the gateway may belong to someone else. See "Open questions".
- IPv4 and IPv6 are separate requests to separate hostnames (`v4.` and `v6.`), each with
  only an A or only an AAAA record, so the client chooses the family by choosing the name.

## API

One endpoint.

```
POST https://v4.probe.example/v1/probe
Content-Type: application/json

{"ports": [5432, 6379, 8080]}
```

- `ports`: 1 to 50 TCP ports. Typically the ports the local scan found published.
- No authentication for the free tier. The source address is the identity.

Response, `200`:

```json
{
  "address": "203.0.113.7",
  "probed_at": "2026-11-19T10:00:00Z",
  "results": [
    {"port": 5432, "state": "open", "service": "PostgreSQL"},
    {"port": 6379, "state": "filtered"},
    {"port": 8080, "state": "closed"}
  ]
}
```

States and service identification are those of the CLI `probe` (same code): `open`,
`closed`, `filtered`, and the same banner read and minimal handshakes. No login attempts.

Errors: `400` invalid body, `413` too many ports, `429` rate limit (with `Retry-After`),
`403` address on the block list or in a reserved range.

The request is synchronous. With a 3 s timeout and 50 ports probed 10 at a time the
worst case is about 15 s.

## Limits

| Limit | Value | Why |
|-------|-------|-----|
| Ports per request | 50 | A scan report rarely lists more. Keeps one request cheap. |
| Requests per source address | 6 per hour, 20 per day | Enough for fix-and-recheck. Useless for sweeping. |
| Requests per /24 (IPv4) or /48 (IPv6) | 60 per hour | Limits a provider-wide script. |
| Connections per request | 10 at a time | Same as the CLI default. |
| Connect timeout | 3 s | Same as the CLI default. |
| Global concurrent requests | fixed worker pool, excess gets `429` | Bounded cost. |

## Abuse protection

- **No target parameter.** See above. The remaining abuse is reflection: making the
  service connect to an address the attacker controls the source of.
- **Reflection needs a spoofed TCP source**, which does not work: the HTTPS request
  requires a completed TCP and TLS handshake from the source address.
- **Shared addresses.** A user behind CGNAT, a corporate proxy, Tor or a VPN exit can
  trigger a probe of that shared address. Mitigations: reject known Tor exits and public
  proxy ranges; reject requests whose TLS client is a browser (the endpoint is for the
  CLI); the per-address rate limit caps the volume at a level any internet host already
  sees from background scanning.
- **Reserved ranges** (private, loopback, link-local, multicast, the service's own
  network) are refused before any connection is made.
- **Opt-out.** A published address where an operator can ask for their range to be
  blocked, and a block list checked before probing.
- **Identification.** Probes come from a small set of documented addresses with reverse
  DNS pointing at a page that explains what the service is and how to opt out.
- **No payloads.** The probe code sends at most one minimal handshake message per port.
  There is no way for a caller to supply bytes to send.

## Data

- Stored per request: timestamp, source address, list of ports, per-port state. Needed
  for rate limiting and abuse handling. Retention: 30 days, then deleted.
- Not stored: banners, anything from the scan report. The client sends port numbers only.
- No account is needed for the free tier, so no email address is collected by this API.

## Client

`dockershield probe --hosted` would:

1. Run the local scan (or read `--from-report`).
2. Print what will be sent (the port list and the fact that the request reveals the
   server's address to the service) and require `--yes` on first use.
3. Call the `v4.` and `v6.` endpoints.
4. Print the same combined view as the two-machine probe.

This is an explicit network command, like `upgrade`. `scan` stays offline.

## Open questions

1. **NAT gateways.** Should the service refuse when the source address is in a range
   known to be CGNAT or a cloud NAT gateway? It cannot always tell.
2. **Who runs the probes.** One location gives one view. A firewall that allows the
   probe's country and blocks others, or the reverse, changes the answer.
3. **Provider terms.** Some hosting providers prohibit outbound port scanning from their
   network, including consensual scanning. The probe hosts need a provider that allows it
   in writing.
4. **Team version.** Scheduled probes of several servers need an identity stronger than
   "the request came from this address": an agent token per server, issued after the
   server proves control of its address once.
5. **Legal.** TODO(Adrian): decide whether this needs terms of service and a privacy
   notice before any public use, and who is the data controller.

## Not planned

- Probing a host named by the user.
- UDP.
- Vulnerability checks beyond "the port answers and looks like service X".
