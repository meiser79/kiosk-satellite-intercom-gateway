# Kiosk Satellite Intercom Gateway

Open **Intercom Gateway** in the sidebar (ingress). There you enter:

1. the **intercom key** (the same one the kiosks use under Intercom),
2. the **PBX** (Asterisk), and
3. per **bridge** the SIP account and the kiosks that should ring.

The configuration lives in `addon_config` (`config.json`) and survives updates.

On each kiosk, *Remote management* and *Intercom* must be on. The gateway detects the kiosk's
*Encrypt communications* setting by itself and follows it per kiosk.

Ports: SIP socket (default UDP 5070), RTP 10000–10100/UDP, kiosk callbacks TCP 2325 and 2326.
The add-on uses the host network because SIP/RTP and the kiosks' callbacks need the real LAN address.
