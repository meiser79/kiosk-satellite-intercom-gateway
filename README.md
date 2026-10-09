# Kiosk Satellite Intercom Gateway (`ks-intercom-gateway`)

Project page: <https://github.com/meiser79/kiosk-satellite-intercom-gateway>

Gateway **SIP → Kiosk Satellite Intercom**. An Asterisk account becomes an extension; when someone calls it, one or more kiosks ring. Whoever answers first talks to the caller.

```
Asterisk ── SIP/RTP (G.711) ──▶ Gateway ── HTTP + WebSocket (PCM16 16 kHz) ──▶ Kiosk(s)
```

## Features
- One SIP account per **bridge** (registration with digest auth) and **several kiosks** per bridge.
- *Ring* mode: all kiosks ring, the first to answer wins, the others are cancelled.
- The kiosk shows the **SIP caller** as the caller: "Name (number)" from the caller's display name and number; for trunk calls `P-Asserted-Identity` is preferred. The name appears on the ring screen, in the log, in missed calls and in the intercom sensor.
- *Announce* mode: one-way audio to all kiosks of the bridge (the kiosk's "announcements" feature).
- Configuration page: intercom key (input only, never sent back), PBX, bridges, a "Test" button per kiosk, status and log.
- Runs as a Docker container or a Home Assistant add-on (ingress, configuration in `addon_config`).

## Not included
Kiosk → SIP (outgoing calls from a kiosk), SRTP/TLS on the SIP side, G.722/Opus, video, music on hold. SIP runs over UDP; codecs are PCMU/PCMA.

## Layout
```
src/main.go          daemon entry point: environment, listeners, wiring
src/gateway/         configuration store, SIP user agent, intercom client, call logic, web UI
src/audio/           G.711 and 8 kHz <-> 16 kHz conversion
tests/               black-box tests: fake PBX and fake kiosk, protocol vectors
config.yaml          Home Assistant add-on manifest (the Dockerfile builds ./src)
repository.yaml      Home Assistant repository descriptor (this repo is a single-add-on repository)
```

## Installation

**Home Assistant (repository):** add <https://github.com/meiser79/kiosk-satellite-intercom-gateway> under *Settings → Add-ons → Add-on store → Repositories*, then install *Kiosk Satellite Intercom Gateway*.

**Home Assistant (local):** create the folder `/addons/ks_intercom_gateway/` (Samba/SSH), copy the contents of this repository into it, refresh *Local add-ons* in the add-on store, install, start.

**Docker:** `docker compose up -d --build`, UI at `http://<host>:8099` (set `UI_USER`/`UI_PASS`; the UI has no login of its own).

## Asterisk (PJSIP)
A normal extension, for example:
```
[2001]
type=endpoint
context=from-internal
disallow=all
allow=ulaw,alaw
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
auth=2001
aors=2001
[2001]
type=auth
auth_type=userpass
username=2001
password=SECRET
[2001]
type=aor
max_contacts=1
```
In FreePBX: create a PJSIP extension, codecs ulaw/alaw, *Direct Media* off.

## Tests
```
go test -race ./tests/
```
The tests start a simulated PBX (REGISTER with digest, INVITE, RTP, BYE) and simulated kiosks (answer, decline, do not disturb, wrong key) and check the full audio path in both directions. The fake PBX and fake kiosk bring their own SIP, digest and token code, so they do not share bugs with the gateway. `tests/token_test.go` pins the token format with a vector computed in Python.

## Protocol
The gateway reimplements Kiosk Satellite's intercom protocol (it does not copy its code): HMAC-SHA256 token (`"intercom:"+KEY`, 60 s, single use), `GET /api/intercom/identity`, `POST /api/intercom/call`, signals `POST /api/intercom/call/<id>`, audio over WebSocket in 80 ms PCM16 frames. The key is a signing secret, not an encryption key; encryption is the kiosks' TLS setting (neither side checks certificates).
