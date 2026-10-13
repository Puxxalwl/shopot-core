import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";

const DIR = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const clean = (s) => s.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "").replace(/\r/g, "");

function mkCli(name) {
  const p = spawn(DIR + "/build/shopot-cli", ["--db", "/tmp/e2e-" + name + ".db", "--dl", "/tmp/e2e-dl-" + name], { stdio: ["pipe", "pipe", "inherit"] });
  let buf = "";
  const waiters = [];
  p.stdout.on("data", (d) => {
    buf += clean(d.toString());
    for (let i = waiters.length - 1; i >= 0; i--) {
      const m = buf.match(waiters[i].re);
      if (m) { waiters[i].res(m); waiters.splice(i, 1); }
    }
  });
  return {
    p,
    send(line) { p.stdin.write(line + "\n"); },
    wait(re, ms = 30000) {
      return new Promise((res, rej) => {
        const m = buf.match(re);
        if (m) return res(m);
        waiters.push({ re, res });
        setTimeout(() => rej(new Error(name + ": timeout " + re + "\n--- tail ---\n" + buf.slice(-800))), ms);
      });
    },
    snapshot: () => buf,
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
writeFileSync("/tmp/e2e-file.bin", Buffer.alloc(1024 * 1024).map((_, i) => (i * 7 + 13) & 0xff));

const alice = mkCli("alice"), bob = mkCli("bob");
await alice.wait(/identity found/); await bob.wait(/identity found/);
alice.send("n"); bob.send("n");
await alice.wait(/YOUR 12 WORDS/); await bob.wait(/YOUR 12 WORDS/);
await alice.wait(/your bundle: (\S+)/); await bob.wait(/your bundle: (\S+)/);
const aBundle = alice.snapshot().match(/your bundle: (\S+)/)[1];
const bBundle = bob.snapshot().match(/your bundle: (\S+)/)[1];
console.log("bundles exchanged out-of-band");

alice.send("add bob " + bBundle);
bob.send("add alice " + aBundle);
await alice.wait(/added contact id=1/);
await bob.wait(/added contact id=1/);

// offline queue: message sent while no session exists
alice.send("msg 1 PRIVET-IZ-OUTBOX (queued while bob offline)");
await alice.wait(/\(queued\)/);
console.log("alice queued a message while offline");

// signaling dance
alice.send("offer 1");
const offerM = await alice.wait(/send this code to the peer:\n(\S+)/, 40000);
bob.send("answer 1 " + offerM[1]);
const answerM = await bob.wait(/send this answer back:\n(\S+)/, 40000);
alice.send("accept 1 " + answerM[1]);

await alice.wait(/ONLINE/, 40000); await bob.wait(/ONLINE/, 40000);
console.log("*** P2P session established (v2 ratchet) ***");

await bob.wait(/PRIVET-IZ-OUTBOX/, 20000);
console.log("*** offline message delivered after handshake ***");
await alice.wait(/delivered/, 20000);
console.log("*** delivery ack received ***");

bob.send("msg 1 i tebja slyshu, alice");
await alice.wait(/i tebja slyshu/, 20000);

// many messages to force ratchet re-keys over the wire (default: every 256)
for (let i = 0; i < 300; i++) bob.send("msg 1 bulk-" + i);
await alice.wait(/bulk-299/, 60000);
console.log("*** 300-message burst delivered (ratchet survived re-keys) ***");

alice.send("send 1 /tmp/e2e-file.bin");
await bob.wait(/file ready: (\S+)/, 60000);
console.log("*** 1 MiB file delivered (64 KiB chunks) ***");

alice.p.kill(); bob.p.kill();
console.log("E2E OK");
process.exit(0);
