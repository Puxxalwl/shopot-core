import { spawn } from "node:child_process";
import { rmSync } from "node:fs";
const DIR = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const clean = (s) => s.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "").replace(/\r/g, "");
for (const f of ["/tmp/inv-alice.db", "/tmp/inv-bob.db"])
  for (const suf of ["", "-wal", "-shm", ".key"]) { try { rmSync(f + suf); } catch {} }

function mkCli(name) {
  const p = spawn(DIR + "/build/shopot-cli", ["--db", "/tmp/inv-" + name + ".db", "--dl", "/tmp/inv-dl-" + name], { stdio: ["pipe", "pipe", "inherit"] });
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
    wait(re, ms = 90000) { return new Promise((res, rej) => {
      const m = buf.match(re);
      if (m) return res(m);
      waiters.push({ re, res });
      setTimeout(() => rej(new Error(name + ": timeout " + re + "\n---\n" + buf.slice(-700))), ms);
    }); },
    snapshot: () => buf };
}

const alice = mkCli("alice"), bob = mkCli("bob");
await alice.wait(/identity found/); await bob.wait(/identity found/);
alice.send("n"); bob.send("n");
await alice.wait(/your bundle:/); await bob.wait(/your bundle:/);

alice.send("invite");
const inv = await alice.wait(/one-time invite code \(share with one person\):\n(\S+)/);
console.log("1. alice generated an invite code (ONE string, one direction)");

bob.send("addi " + inv[1] + " bob");
await bob.wait(/added pending invite as contact id=1/);
console.log("2. bob accepted it - alice's bundle arrived with the code itself");

alice.send("auto");          // inviter: listen on unused invite topics
bob.send("auto 1");          // acceptor: redeem + connect
await alice.wait(/new contact from invite: id=1/, 90000);
console.log("3. bob's bundle arrived sealed; alice added him automatically");
await alice.wait(/\[1\] ONLINE/, 90000);
await bob.wait(/\[1\] ONLINE/, 90000);
console.log("*** P2P session established via ONE-WAY invite ***");

bob.send("msg 1 privet-po-invite");
await alice.wait(/privet-po-invite/, 30000);
alice.send("msg 1 otvet-po-invite");
await bob.wait(/otvet-po-invite/, 30000);
console.log("*** messages flow both ways ***");

alice.p.kill(); bob.p.kill();
console.log("INVITE-E2E OK");
process.exit(0);
