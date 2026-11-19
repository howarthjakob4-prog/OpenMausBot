// Validates relay-lib.mjs against the wire spec's published test vectors
// (companion/src/e2e/vectors/v1.json in the fork).
import { readFileSync } from "node:fs";
import {
  RecordCipher, admissionFor, computerAccept, credentialHash, dh, encodeFrame,
  keyIdOf, keyPairFromPrivate, phoneHello, pskFor,
} from "./relay-lib.mjs";

const V = JSON.parse(readFileSync(
  "/home/hatch/workspace/projects/openmausbot-study/src/OpenMausBot-main/companion/src/e2e/vectors/v1.json",
  "utf8",
));
const hex = (s) => Buffer.from(s, "hex");
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
let passed = 0, failed = 0;
function check(name, ok, detail = "") {
  if (ok) { passed += 1; console.log(`PASS ${name}`); }
  else { failed += 1; console.log(`FAIL ${name} ${detail}`); }
}

// ---- V1: identities and derivations --------------------------------------
const inputs = V.inputs;
const transport = keyPairFromPrivate(hex(inputs.transportPrivate));
check("V1 transportPublic", eq(transport.publicKey, hex(V.V1.transportPublic)));
const keyId = keyIdOf(transport.publicKey);
check("V1 keyId", eq(keyId, hex(V.V1.keyId)));
const hostId = hex(inputs.hostId);
for (const want of V.V1.credentials) {
  const label = want.name;
  const cred = want.token;
  const credHash = credentialHash(cred);
  check(`V1 ${label} credHash`, eq(credHash, hex(want.credHash)), `got ${credHash.toString("hex")} want ${want.credHash}`);
  check(`V1 ${label} psk`, eq(pskFor(credHash, keyId), hex(want.psk)));
  check(`V1 ${label} adm`, eq(admissionFor(credHash, hostId), hex(want.adm)));
}
const phoneEph = keyPairFromPrivate(hex(inputs.phoneEphemeralPrivate));
const computerEph = keyPairFromPrivate(hex(inputs.computerEphemeralPrivate));
check("V1 phone ephemeral public", eq(phoneEph.publicKey, hex(V.V1.phoneEphemeralPublic)));
check("V1 computer ephemeral public", eq(computerEph.publicKey, hex(V.V1.computerEphemeralPublic)));
check("V1 dh es", eq(dh(hex(inputs.transportPrivate), phoneEph.publicKey), hex(V.V1.dh.es)));
check("V1 dh ee", eq(dh(hex(inputs.phoneEphemeralPrivate), computerEph.publicKey), hex(V.V1.dh.ee)));

// ---- V2: handshake over the relay with the device psk ---------------------
const devicePsk = pskFor(credentialHash(inputs.deviceToken), keyId);
const payload1 = Buffer.from(inputs.payload1, "utf8");
const hello = phoneHello(
  { remoteStatic: transport.publicKey, psk: devicePsk, transport: 1, ephemeral: phoneEph },
  payload1,
  inputs.connB64u,
);
check("V2 message1", eq(hello.message1, hex(V.V2.message1)), `got ${hello.message1.toString("hex").slice(0, 40)}…`);
const accepted = computerAccept(
  { staticKey: transport, transport: 1, candidates: [{ id: "device", psk: devicePsk }], ephemeral: computerEph },
  hello.message1,
);
check("V2 computer accepts", accepted !== null);
if (accepted) {
  check("V2 message2", eq(accepted.message2, hex(V.V2.message2)));
  check("V2 computer kPc", eq(accepted.keys.kPc, hex(V.V2.kPc)));
  check("V2 computer kCp", eq(accepted.keys.kCp, hex(V.V2.kCp)));
  check("V2 computer handshakeHash", eq(accepted.keys.handshakeHash, hex(V.V2.handshakeHash)));
  const phoneKeys = hello.finish(accepted.message2);
  check("V2 phone kPc", eq(phoneKeys.kPc, hex(V.V2.kPc)));
  check("V2 phone kCp", eq(phoneKeys.kCp, hex(V.V2.kCp)));
  check("V2 phone handshakeHash", eq(phoneKeys.handshakeHash, hex(V.V2.handshakeHash)));

  // ---- V4: transport records of the V2 session ---------------------------
  const pc = new RecordCipher(phoneKeys.send.state);
  const cpSend = new RecordCipher(accepted.keys.send.state);
  const cpRecv = new RecordCipher(phoneKeys.receive.state);
  for (const record of V.V4.records) {
    const frame = hex(record.frame);
    if (record.direction === "pc") {
      check(`V4 pc record n=${record.n}`, eq(pc.seal(frame), hex(record.record)));
    } else {
      const sealed = cpSend.seal(frame);
      check(`V4 cp record n=${record.n}`, eq(sealed, hex(record.record)));
      check(`V4 cp record opens`, eq(cpRecv.open(sealed), frame));
    }
  }
}

// ---- V5: yamux frames byte for byte ---------------------------------------
for (const item of V.V5) {
  const want = hex(item.hex);
  const data = item.type === 0 ? want.subarray(12) : undefined;
  const frame = { type: item.type, flags: item.flags, streamId: item.streamId, length: item.length, data };
  try {
    check(`V5 ${item.name}`, eq(encodeFrame(frame), want));
  } catch (error) {
    check(`V5 ${item.name}`, false, String(error));
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
