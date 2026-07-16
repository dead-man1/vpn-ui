// Node test for web/assets/js/model/inbound.js: the client MODEL invariants that
// the panel's shared, id-keyed client plumbing depends on.
//
// Why this exists as a host-side test: the incus E2E drives the panel's HTTP API and
// posts client JSON directly (with an explicit "id"), so it never runs this file at
// all. A model bug here is therefore invisible to a fully green E2E and only shows up
// in the browser. That is not hypothetical: mtproto and wg-c both identify accounts
// by EMAIL and synthesize id=email in toJson(), but fromJson() rebuilds them through
// a constructor that takes no id: so the LIVE object had no .id while its serialized
// form did. Every id-keyed path then broke: the client modal's oldClientId became
// undefined, edits POSTed to /updateClient/undefined and the panel answered "empty
// client ID", and the client table's :row-key went undefined for every row.
"use strict";
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "..", "..");
const failures = [];
function ok(cond, msg) {
  if (cond) console.log("  ok   " + msg);
  else { console.log("  FAIL " + msg); failures.push(msg); }
}

// ---- load the REAL panel model under Node -------------------------------
// inbound.js is a browser script (no module exports), so evaluate it with the few
// globals it touches and lift the classes out. Loading the real file is the point:
// a hand-copied model would not catch a regression in the shipped one.
// window.crypto: RandomUtil mints the default random email/secret through it, so the
// "add a client" path touches it during construction.
global.window = {
  location: { hostname: "example.com" },
  crypto: require("crypto").webcrypto,
};
global.document = { addEventListener() {} };
const src =
  fs.readFileSync(path.join(REPO, "web/assets/js/util/index.js"), "utf8") + "\n" +
  fs.readFileSync(path.join(REPO, "web/assets/js/model/inbound.js"), "utf8") +
  "\nglobalThis.__Inbound = Inbound; globalThis.__Protocols = Protocols;";
(0, eval)(src);
const Inbound = globalThis.__Inbound;

console.log("model: email-identity clients expose .id");

// Both protocols whose identity is the email rather than a username/password.
const CASES = [
  { name: "MtprotoUser", cls: Inbound.MtprotoSettings.MtprotoUser,
    stored: { email: "alice@t", id: "alice@t", secret: "a".repeat(32), enable: true,
              modeClassic: true, modeSecure: false, modeTls: false,
              tlsDomain: "www.google.com", userLimit: 0, externalProxy: [] } },
  { name: "WgUser", cls: Inbound.WgcSettings.WgUser,
    stored: { email: "bob@t", id: "bob@t", enable: true,
              privKey: "k", pubKey: "p", psk: "" } },
];

for (const { name, cls, stored } of CASES) {
  // fromJson is the path the client table uses (dbInbound.toInbound()), and the one
  // that used to drop id on the floor.
  const live = cls.fromJson([stored])[0];
  ok(live.id === stored.email,
     `${name}: live object rehydrated by fromJson exposes id (got ${JSON.stringify(live.id)})`);
  ok(live.toJson().id === live.id,
     `${name}: serialized id matches the live object's id`);

  // A getter, not a copied field: the identity must follow a rename rather than go
  // stale, since the panel matches the posted client by this value.
  live.email = "renamed@t";
  ok(live.id === "renamed@t",
     `${name}: id follows an email rename (cannot go stale)`);

  // A freshly constructed client (the "add" path) must be id-keyed too.
  const fresh = new cls();
  ok(typeof fresh.id === "string" && fresh.id.length > 0 && fresh.id === fresh.email,
     `${name}: newly constructed client has id === email`);
}

// ---- verdict ------------------------------------------------------------
console.log("");
if (failures.length) {
  console.log("FAIL: " + failures.length + " assertion(s) failed:");
  failures.forEach((f) => console.log("  - " + f));
  process.exit(1);
}
console.log("PASS: inbound.js model invariants all good");
