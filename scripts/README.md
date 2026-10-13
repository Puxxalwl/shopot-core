# End-to-end scripts

Both scripts spin up two real CLI processes on one machine and run a full
conversation over real WebRTC (DTLS, ICE, the works). Node >= 18 required.

```bash
# manual signaling: bundle -> offer -> answer code exchange
node scripts/e2e-manual.mjs

# automatic rendezvous: both sides just "auto 1", zero codes
node scripts/e2e-auto.mjs
```

Expect ~10-30 s. Exit 0 + "E2E OK" / "AUTO-E2E OK" means everything passed:
handshake, offline-queue flush, delivery acks, a message burst through
ratchet re-keys, and a file transfer (manual script).

For signal-layer traces set SHOPOT_SIGNAL_DEBUG=1. The rendezvous relay is a
public MQTT broker; a network without outbound TLS will fail the auto script.
