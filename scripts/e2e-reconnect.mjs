import { spawn } from "node:child_process";
import { rmSync } from "node:fs";
const DIR = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const clean = (s) => s.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "").replace(/\r/g, "");
for (const f of ["/tmp/rc-alice.db", "/tmp/rc-bob.db"])
  for (const suf of ["", "-wal", "-shm", ".key"]) { try { rmSync(f + suf); } catch {} }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function mkCli(name) {
  const p = spawn(DIR + "/build/shopot-cli", ["--db", "/tmp/rc-" + name + ".db", "--dl", "/tmp/rc-dl-" + name], { stdio: ["pipe", "pipe", "inherit"] });
  let buf = "";
  const waiters = [];
  p.stdout.on("data", (d) => {
    buf += clean(d.toString());
    for (let i = waiters.length - 1; i >= 0; i--) {
      const m = buf.match(waiters[i].re);
      if (m) { waiters[i].res(m); waiters.splice(i, 1); }
    }
  });
  return { p, send: (l) => p.stdin.write(l + "\n"),
    wait(re, ms = 60000) { return new Promise((res, rej) => {
      const m = buf.match(re);
      if (m) return res(m);
      waiters.push({ re, res });
      setTimeout(() => rej(new Error(name + ": timeout " + re + "\n---\n" + buf.slice(-700))), ms);
    }); },
    waitCount(re, n, ms = 90000) { return new Promise((res, rej) => {
      const t0 = Date.now();
      const tick = () => {
        if (buf.split(re).length - 1 >= n) return res(true);
        if (Date.now() - t0 > ms) return rej(new Error(name + ": count timeout " + re + "\n---\n" + buf.slice(-700)));
        setTimeout(tick, 300);
      };
      tick();
    }); },
    snapshot: () => buf };
}

const alice = mkCli("alice");
let bob = mkCli("bob");
await alice.wait(/identity found/); await bob.wait(/identity found/);
alice.send("n"); bob.send("n");
await alice.wait(/your bundle:/); await bob.wait(/your bundle:/);
const aBundle = alice.snapshot().match(/your bundle: (\S+)/)[1];
const bBundle = bob.snapshot().match(/your bundle: (\S+)/)[1];
alice.send("add bob " + bBundle);
bob.send("add alice " + aBundle);
await alice.wait(/added contact id=1/); await bob.wait(/added contact id=1/);

alice.send("auto 1"); bob.send("auto 1");
await alice.waitCount(/\[1\] ONLINE/, 1);
await bob.waitCount(/\[1\] ONLINE/, 1);
bob.send("msg 1 do-razryva");
await alice.wait(/do-razryva/);
console.log("1. connected, chat works");

// --- bob exits; alice sends while he is offline ---
bob.p.kill();
await sleep(1500);
alice.send("msg 1 oflajn-test-posle-restarta");
await alice.wait(/\(queued\)/);
await sleep(2000);
if (alice.snapshot().includes("oflajn-test-posle-restarta\n")) {}
console.log("2. bob exited; alice queued a message (not delivered yet)");

// --- bob returns with the SAME db; keepers reconnect on their own ---
bob = mkCli("bob");
await bob.wait(/your bundle:/);
console.log("3. bob is back (same db); no manual 'auto' - keepers work");
await alice.waitCount(/\[1\] ONLINE/, 2, 90000);
await bob.waitCount(/\[1\] ONLINE/, 1, 90000);
await alice.wait(/\(delivered /, 30000);          // the queued message got acked
await bob.wait(/oflajn-test-posle-restarta/, 30000); // and arrived
console.log("*** queued message flushed automatically after reconnect ***");

bob.send("msg 1 posle-vozvrata");
await alice.wait(/posle-vozvrata/, 30000);
console.log("*** new messages flow too ***");

alice.p.kill(); bob.p.kill();
console.log("RECONNECT-E2E OK");
process.exit(0);
