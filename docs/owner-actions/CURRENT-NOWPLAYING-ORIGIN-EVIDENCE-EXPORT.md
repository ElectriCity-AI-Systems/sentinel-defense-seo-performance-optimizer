# Current NowPlaying Origin Evidence Export - Owner Installation Packet

Classification: PRIVATE_OWNER_OPERATIONAL_DOCUMENT | NOT_FOR_PUBLIC_RELEASE

## Status

This packet is prepared for owner review only. It has not been installed on the
origin and Sentinel has not written to the origin.

## Files

Repository sources:

```text
origin-readonly/sentinel-origin-evidence-window.py
origin-readonly/sentinel-origin-evidence-window.dispatch.inc
```

Reviewed origin target:

```text
/usr/local/libexec/sentinel-origin-evidence-window.py
owner=root
group=root
mode=0755
```

The dispatch fragment must be merged manually into the existing root-owned
forced-command gateway for the existing `sentinel-ro` account. The gateway path
is deliberately not guessed.

## Security Boundary

The command accepts exactly four whitespace-separated tokens:

```text
sentinel-origin-evidence-window EVIDENCE_TYPE START_UTC END_UTC
```

Enabled evidence types:

```text
nginx-window
nginx-error-window
nowplaying-window
```

All enabled types are fixed to:

```text
/api/nowplaying/electri-city-ai-electro-radio
```

`azuracast-window` remains denied because no owner-reviewed fixed AzuraCast log
source is known. It must not be enabled by adding a caller-supplied path or
service name.

Validation is fail-closed:

- timestamps must use exact `YYYY-MM-DDTHH:MM:SSZ` UTC form;
- start must precede end;
- the interval must not exceed 60 minutes;
- end must not be in the future;
- start must be within the preceding 48 hours;
- evidence type, endpoint, source files, and output fields are source allowlists;
- extra tokens, paths, shell operators, newlines, sudo, and arbitrary commands are denied;
- symlinked, oversized, group-writable, or world-writable source logs are denied;
- records, lines, source bytes, and serialized output have fixed upper bounds;
- query strings, raw user agents, headers, cookies, credentials, and raw error messages are omitted.

The helper invokes no shell, subprocess, network client, sudo operation, or
writer. The only variable data are the evidence type and validated recent UTC
window. A deterministic query ID makes an invocation auditable without storing
credentials or raw command material.

## Current Window Example

After owner installation, the only recommended collection command for this
incident is:

```bash
ssh sentinel-nowplaying-origin \
  'sentinel-origin-evidence-window nowplaying-window 2026-09-07T15:15:54Z 2026-09-07T15:30:37Z' \
  > /srv/sentinel-defense/data/origin-evidence/nowplaying-origin-window-20260907.json
chmod 0600 /srv/sentinel-defense/data/origin-evidence/nowplaying-origin-window-20260907.json
```

This command is not executed by this packet.

## Owner Installation

Using the existing administrative channel, the owner would first inspect and
test the source locally, then install it manually:

```bash
python3 origin-readonly/sentinel-origin-evidence-window.py --self-test
sudo install -o root -g root -m 0755 \
  origin-readonly/sentinel-origin-evidence-window.py \
  /usr/local/libexec/sentinel-origin-evidence-window.py
```

Merge the exact dispatch branch before the gateway's default deny branch. Do
not replace it with a wildcard command executor, `eval`, `sh -c`, a path
argument, a grep expression, or sudo forwarding.

## Tests Before Installation

Required review checks:

```text
ORIGIN_EVIDENCE_WINDOW_SELF_TEST_OK
valid fixed current window accepted
window over 60 minutes denied
future and older-than-48-hour windows denied
unknown and unreviewed evidence types denied
extra paths and shell syntax denied
unrelated endpoints omitted
raw nginx errors omitted and classified
output limits enforced
```

The owner must also verify that every finite source filename matches the actual
origin layout and that `sentinel-ro` needs no broader filesystem access.

## Rollback

Rollback is manual and limited to the installed evidence lane:

1. Remove only the added dispatch branch.
2. Remove only `/usr/local/libexec/sentinel-origin-evidence-window.py`.
3. Verify that the historical fixed command still behaves unchanged.
4. Verify that arbitrary SSH commands remain denied.

No nginx, AzuraCast, Cloudflare, DNS, TLS, WAF, cache, polling, or autonomy
configuration is changed by installation or rollback.
