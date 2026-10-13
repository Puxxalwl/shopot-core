# End-to-end scripts

Both scripts spin up two real CLI processes on one machine and run a full
conversation over real WebRTC (DTLS, ICE, the works). Node >= 18 required.

```bash
# manual signaling: bundle -> offer -> answer code exchange
node scripts/e2e-manual.mjs

# automatic rendezvous: both sides just "auto 1", zero codes
node scripts/e2e-auto.mjs

# one-way invites: a single "shopot://i/..." string, no bundle exchange
node scripts/e2e-invite.mjs

# peer exits and returns with the same db; the keeper reconnects on its own
# and the queued message flushes (no manual 'auto')
node scripts/e2e-reconnect.mjs
```

Expect ~10-60 s. Exit 0 + "E2E OK" / "AUTO-E2E OK" / "INVITE-E2E OK" /
"RECONNECT-E2E OK" means everything passed: handshake, offline-queue flush,
delivery acks, a message burst through ratchet re-keys, and a file transfer
(manual script).

For signal-layer traces set SHOPOT_SIGNAL_DEBUG=1. The rendezvous relay is a
public MQTT broker; a network without outbound TLS will fail the auto script.
