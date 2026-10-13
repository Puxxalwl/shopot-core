import { spawn } from "node:child_process";
import { writeFileSync, rmSync } from "node:fs";

const DIR = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const clean = (s) => s.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "").replace(/\r/g, "");

for (const f of ["/tmp/auto-alice.db", "/tmp/auto-bob.db"]) {
  for (const suf of ["", "-wal", "-shm", ".key"]) { try { rmSync(f + suf); } catch {} }
}

function mkCli(name) {
  const p = spawn(DIR + "/build/shopot-cli", ["--db", "/tmp/auto-" + name + ".db", "--dl", "/tmp/auto-dl-" + name], { stdio: ["pipe", "pipe", "inherit"] });
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
    wait(re, ms = 45000) {
      return new Promise((res, rej) => {
        const m = buf.match(re);
        if (m) return res(m);
        waiters.push({ re, res });
        setTimeout(() => rej(new Error(name + ": timeout " + re + "\n--- tail ---\n" + buf.slice(-600))), ms);
      });
    },
    snapshot: () => buf,
  };
}

const alice = mkCli("alice"), bob = mkCli("bob");
await alice.wait(/identity found/); await bob.wait(/identity found/);
alice.send("n"); bob.send("n");
await alice.wait(/your bundle: (\S+)/); await bob.wait(/your bundle: (\S+)/);
const aBundle = alice.snapshot().match(/your bundle: (\S+)/)[1];
const bBundle = bob.snapshot().match(/your bundle: (\S+)/)[1];
console.log("1. bundles exchanged out-of-band (the ONLY manual step ever)");

alice.send("add bob " + bBundle);
bob.send("add alice " + aBundle);
await alice.wait(/added contact id=1/); await bob.wait(/added contact id=1/);

// automatic discovery: no codes at all
alice.send("auto 1");
bob.send("auto 1");
console.log("2. both sides: auto 1  (rendezvous via public relay, sealed payloads)");
await alice.wait(/\(online\)|ONLINE/, 90000);
await bob.wait(/\(online\)|ONLINE/, 90000);
console.log("*** P2P session established with ZERO code exchange ***");

alice.send("msg 1 privat-no-codes");
await bob.wait(/privat-no-codes/, 20000);
console.log("*** message delivered over the auto-established session ***");
bob.send("msg 1 otvet poluchen");
await alice.wait(/otvet poluchen/, 20000);
console.log("*** reply works too ***");

alice.p.kill(); bob.p.kill();
console.log("AUTO-E2E OK");
process.exit(0);
