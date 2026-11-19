// Ferrum relay client library — an independent implementation of the OpenMausBot
// E2E phone wire protocol, written from the published spec
// (companion/src/e2e/README.md, wire spec v1) in Jakob's fork of OpenMausBot
// (Apache-2.0). This file is the reference the Android port is built from.
//
// Layers: credential derivations -> Noise_NKpsk0_P256_AESGCM_SHA256 handshake ->
// AEAD records carrying yamux frames -> streams carrying HTTP/1.1.
import {
  createCipheriv, createDecipheriv, createECDH, createHash, createHmac,
  hkdfSync, randomBytes,
} from "node:crypto";

// ---------------------------------------------------------------------------
// base64url, strict (canonical, unpadded)
const B64U_RE = /^[A-Za-z0-9_-]*$/;
export const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
export function fromB64u(text) {
  if (typeof text !== "string" || !B64U_RE.test(text) || text.length % 4 === 1) return null;
  const bytes = Buffer.from(text, "base64url");
  return bytes.toString("base64url") === text ? bytes : null;
}

export const sha256 = (data) => createHash("sha256").update(data).digest();
export const hmacSha256 = (key, msg) => createHmac("sha256", key).update(msg).digest();

// ---------------------------------------------------------------------------
// Credential derivations (spec section 2)
export const credentialHash = (token) => sha256(Buffer.from(token, "utf8"));
export const keyIdOf = (transportPub) => sha256(transportPub).subarray(0, 16);
export const pskFor = (credHash, keyId) =>
  hmacSha256(credHash, Buffer.concat([Buffer.from("omb-e2e psk v1", "utf8"), keyId]));
export const admissionFor = (credHash, hostId) =>
  hmacSha256(credHash, Buffer.concat([Buffer.from("omb-relay admission v1", "utf8"), hostId]));

// ---------------------------------------------------------------------------
// Pairing link parsing (spec section 3)
export function parsePairingLink(link) {
  const url = new URL(link);
  if (url.protocol !== "openmausbot:") throw new Error("not an openmausbot link");
  const token = url.searchParams.get("token");
  const name = url.searchParams.get("name") ?? "";
  const e2eRaw = url.searchParams.get("e2e");
  if (!token) throw new Error("pairing link has no token");
  if (!e2eRaw) throw new Error("pairing link has no e2e descriptor");
  const e2eBytes = fromB64u(e2eRaw);
  if (!e2eBytes) throw new Error("e2e descriptor is not strict base64url");
  const e2e = JSON.parse(e2eBytes.toString("utf8"));
  if (e2e.v !== 1) throw new Error(`e2e version ${e2e.v}: update required`);
  const transportPub = fromB64u(e2e.k);
  if (!transportPub || transportPub.length !== 65 || transportPub[0] !== 0x04) {
    throw new Error("e2e descriptor has a bad transport key");
  }
  const hostId = e2e.h ? fromB64u(e2e.h) : null;
  const relays = Array.isArray(e2e.r) ? e2e.r : [];
  if ((hostId && relays.length === 0) || (!hostId && relays.length > 0)) {
    throw new Error("e2e descriptor: h and r must come together");
  }
  for (const host of relays) {
    if (!/^relay[1-9][0-9]?\.openmausbot\.com$/.test(host)) throw new Error(`relay host not allowed: ${host}`);
  }
  if (hostId && hostId.length !== 16) throw new Error("e2e descriptor has a bad hostId");
  return { token, name, transportPub, hostId, relays };
}

// ---------------------------------------------------------------------------
// P-256
function ecdhFrom(privateKey) {
  const curve = createECDH("prime256v1");
  if (privateKey) curve.setPrivateKey(privateKey);
  else curve.generateKeys();
  return curve;
}
export function keyPairFromPrivate(privateKey) {
  const curve = ecdhFrom(privateKey);
  const raw = curve.getPrivateKey();
  return {
    privateKey: Buffer.concat([Buffer.alloc(32 - raw.length), raw]),
    publicKey: curve.getPublicKey(null, "uncompressed"),
  };
}
export const generateKeyPair = () => keyPairFromPrivate(undefined);
export function dh(privateKey, publicKey) {
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) throw new Error("bad_point");
  return ecdhFrom(privateKey).computeSecret(publicKey);
}

// ---------------------------------------------------------------------------
// Noise_NKpsk0_P256_AESGCM_SHA256 (spec section 5)
export const PROTOCOL_NAME = "Noise_NKpsk0_P256_AESGCM_SHA256";
export const TRANSPORT_RELAY = 0x01;
export const TRANSPORT_DIRECT = 0x02;
const TAG = 16;

function hkdf(ck, ikm, outputs) {
  const out = Buffer.from(hkdfSync("sha256", ikm, ck, Buffer.alloc(0), 32 * outputs));
  return Array.from({ length: outputs }, (_, i) => out.subarray(i * 32, i * 32 + 32));
}
function nonceBytes(n) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(n), 4);
  return nonce;
}
function aeadSeal(key, n, ad, plaintext) {
  const cipher = createCipheriv("aes-256-gcm", key, nonceBytes(n), { authTagLength: TAG });
  cipher.setAAD(ad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}
function aeadOpen(key, n, ad, ciphertext) {
  if (ciphertext.length < TAG) throw new Error("short_ciphertext");
  const decipher = createDecipheriv("aes-256-gcm", key, nonceBytes(n), { authTagLength: TAG });
  decipher.setAAD(ad);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - TAG));
  return Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.length - TAG)),
    decipher.final(),
  ]);
}

class CipherState {
  constructor(key = null, n = 0) { this.key = key; this.n = n; }
  encryptWithAd(ad, plaintext) {
    if (!this.key) return Buffer.from(plaintext);
    const out = aeadSeal(this.key, this.n, ad, plaintext);
    this.n += 1;
    return out;
  }
  decryptWithAd(ad, ciphertext) {
    if (!this.key) return Buffer.from(ciphertext);
    const out = aeadOpen(this.key, this.n, ad, ciphertext);
    this.n += 1;
    return out;
  }
}

class SymmetricState {
  constructor(h, ck) { this.h = h; this.ck = ck; this.cipher = new CipherState(); }
  static initialize() {
    const name = Buffer.from(PROTOCOL_NAME, "utf8");
    const h = name.length <= 32
      ? Buffer.concat([name, Buffer.alloc(32 - name.length)])
      : sha256(name);
    return new SymmetricState(h, Buffer.from(h));
  }
  clone() {
    const copy = new SymmetricState(Buffer.from(this.h), Buffer.from(this.ck));
    copy.cipher = this.cipher;
    return copy;
  }
  mixHash(data) { this.h = sha256(Buffer.concat([this.h, data])); }
  mixKey(ikm) {
    const [ck, key] = hkdf(this.ck, ikm, 2);
    this.ck = ck;
    this.cipher = new CipherState(key);
  }
  mixKeyAndHash(ikm) {
    const [ck, tempH, key] = hkdf(this.ck, ikm, 3);
    this.ck = ck;
    this.mixHash(tempH);
    this.cipher = new CipherState(key);
  }
  encryptAndHash(plaintext) {
    const out = this.cipher.encryptWithAd(this.h, plaintext);
    this.mixHash(out);
    return out;
  }
  decryptAndHash(ciphertext) {
    const out = this.cipher.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return out;
  }
  split() {
    const [a, b] = hkdf(this.ck, Buffer.alloc(0), 2);
    return [new CipherState(a), new CipherState(b)];
  }
}

export const prologue = (transport) =>
  Buffer.concat([Buffer.from("omb-e2e/1", "utf8"), Buffer.from([0x00, transport])]);

function initialized(transport, responderStatic) {
  const state = SymmetricState.initialize();
  state.mixHash(prologue(transport));
  state.mixHash(responderStatic);
  return state;
}

export class RecordCipher {
  constructor(cipherState) { this.state = cipherState; }
  get nonce() { return this.state.n; }
  seal(plaintext) {
    if (plaintext.length > 65535 - TAG) throw new Error("record_too_large");
    return this.state.encryptWithAd(Buffer.alloc(0), plaintext);
  }
  open(record) {
    if (record.length > 65535) throw new Error("record_too_large");
    return this.state.decryptWithAd(Buffer.alloc(0), record);
  }
}

function sessionKeys(state, side) {
  const [pc, cp] = state.split();
  return side === "phone"
    ? { send: new RecordCipher(pc), receive: new RecordCipher(cp), handshakeHash: state.h, kPc: pc.key, kCp: cp.key }
    : { send: new RecordCipher(cp), receive: new RecordCipher(pc), handshakeHash: state.h, kPc: pc.key, kCp: cp.key };
}

export const encodePayload1 = (connBytes, app) =>
  Buffer.from(JSON.stringify({ v: 1, conn: b64u(connBytes), app }), "utf8");
export const encodePayload2 = (conn) =>
  Buffer.from(JSON.stringify({ v: 1, conn }), "utf8");

/** Initiator handshake. Returns { message1, finish(message2) -> SessionKeys }. */
export function phoneHello({ remoteStatic, psk, transport, ephemeral }, payload1, conn) {
  if (psk.length !== 32) throw new Error("bad_psk");
  if (payload1.length > 512) throw new Error("payload_too_large");
  const state = initialized(transport, remoteStatic);
  state.mixKeyAndHash(psk);
  const e = ephemeral ?? generateKeyPair();
  state.mixHash(e.publicKey);
  state.mixKey(e.publicKey);
  state.mixKey(dh(e.privateKey, remoteStatic));
  const message1 = Buffer.concat([e.publicKey, state.encryptAndHash(payload1)]);
  let done = false;
  return {
    message1,
    finish(message2) {
      if (done) throw new Error("finished");
      done = true;
      if (message2.length < 65 + TAG || message2.length > 65 + 512 + TAG) throw new Error("message2_size");
      const re = message2.subarray(0, 65);
      const ee = dh(e.privateKey, re);
      state.mixHash(re);
      state.mixKey(re);
      state.mixKey(ee);
      const payload2 = state.decryptAndHash(message2.subarray(65));
      let parsed = null;
      try { parsed = JSON.parse(payload2.toString("utf8")); } catch { /* handled below */ }
      if (!parsed || parsed.v !== 1) throw new Error("payload2_version");
      if (parsed.conn !== conn) throw new Error("payload2_conn");
      return sessionKeys(state, "phone");
    },
  };
}

/** Responder handshake (used by the vector tests and local mocks). */
export function computerAccept({ staticKey, transport, candidates, ephemeral }, message1) {
  if (message1.length < 65 + TAG || message1.length > 65 + 512 + TAG) return null;
  const re = message1.subarray(0, 65);
  let es;
  try { es = dh(staticKey.privateKey, re); } catch { return null; }
  const base = initialized(transport, staticKey.publicKey);
  let match = null;
  for (const candidate of candidates) {
    if (candidate.psk.length !== 32) continue;
    const state = base.clone();
    state.mixKeyAndHash(candidate.psk);
    state.mixHash(re);
    state.mixKey(re);
    state.mixKey(es);
    try {
      const payload = state.decryptAndHash(message1.subarray(65));
      match ??= { id: candidate.id, state, payload };
    } catch { /* not this device */ }
  }
  if (!match) return null;
  let payload1 = null;
  try { payload1 = JSON.parse(match.payload.toString("utf8")); } catch { return null; }
  if (!payload1 || payload1.v !== 1 || typeof payload1.conn !== "string") return null;
  if (!fromB64u(payload1.conn) || fromB64u(payload1.conn).length !== 16) return null;
  const { state } = match;
  const e = ephemeral ?? generateKeyPair();
  state.mixHash(e.publicKey);
  state.mixKey(e.publicKey);
  state.mixKey(dh(e.privateKey, re));
  const message2 = Buffer.concat([e.publicKey, state.encryptAndHash(encodePayload2(payload1.conn))]);
  return { id: match.id, payload1, message2, keys: sessionKeys(state, "computer") };
}

// ---------------------------------------------------------------------------
// yamux profile (spec section 7) — phone role
export const YTYPE = { data: 0, windowUpdate: 1, ping: 2, goAway: 3 };
export const YFLAG = { syn: 0x1, ack: 0x2, fin: 0x4, rst: 0x8 };
const INITIAL_WINDOW = 256 * 1024;
const OPEN_DELTA = 2 * 1024 * 1024 - INITIAL_WINDOW;
const MAX_DATA = 65507;

export function encodeFrame({ type, flags, streamId, length, data }) {
  const payload = type === YTYPE.data ? data ?? new Uint8Array(0) : new Uint8Array(0);
  const out = Buffer.alloc(12 + payload.length);
  out.writeUInt8(0, 0);
  out.writeUInt8(type, 1);
  out.writeUInt16BE(flags, 2);
  out.writeUInt32BE(streamId, 4);
  out.writeUInt32BE(length, 8);
  out.set(payload, 12);
  return out;
}
export function decodeFrame(bytes) {
  const view = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.length < 12) throw new Error("short_frame");
  if (view.readUInt8(0) !== 0) throw new Error("version");
  const type = view.readUInt8(1);
  if (type > 3) throw new Error("type");
  const flags = view.readUInt16BE(2);
  if ((flags & ~0xf) !== 0) throw new Error("flags");
  const streamId = view.readUInt32BE(4);
  const length = view.readUInt32BE(8);
  if (type === YTYPE.data) {
    if (length > MAX_DATA || view.length !== 12 + length) throw new Error("data_length");
    if (streamId === 0) throw new Error("stream_zero");
    return { type, flags, streamId, length, data: view.subarray(12) };
  }
  if (view.length !== 12) throw new Error("trailing_bytes");
  return { type, flags, streamId, length };
}

class MuxStream {
  constructor(session, id) {
    this.session = session;
    this.id = id;
    this.sendWindow = INITIAL_WINDOW;
    this.receiveWindow = INITIAL_WINDOW + OPEN_DELTA;
    this.uncredited = 0;
    this.established = false;
    this.localFin = false;
    this.remoteFin = false;
    this.resetFlag = false;
    this.readBuffer = [];
    this.readWaiters = [];
    this.writeQueue = [];
    this.acceptWaiters = [];
  }
  // -- sending -------------------------------------------------------------
  write(data) {
    return new Promise((resolve, reject) => {
      this.writeQueue.push({ data: Buffer.from(data), offset: 0, resolve, reject });
      this.#flush();
    });
  }
  #flush() {
    while (this.writeQueue.length > 0) {
      const head = this.writeQueue[0];
      const remaining = head.data.length - head.offset;
      if (remaining === 0) { this.writeQueue.shift(); head.resolve(); continue; }
      const size = Math.min(remaining, this.sendWindow, MAX_DATA);
      if (size === 0) return;
      this.sendWindow -= size;
      const chunk = head.data.subarray(head.offset, head.offset + size);
      head.offset += size;
      this.session.sendFrame({ type: YTYPE.data, flags: 0, streamId: this.id, length: chunk.length, data: chunk });
    }
  }
  onWritable() { this.#flush(); }
  end() {
    if (this.localFin) return;
    this.localFin = true;
    this.session.sendFrame({ type: YTYPE.windowUpdate, flags: YFLAG.fin, streamId: this.id, length: 0 });
  }
  // -- receiving -----------------------------------------------------------
  deliver(data) {
    this.receiveWindow -= data.length;
    if (data.length > 0) this.readBuffer.push(Buffer.from(data));
    this.#wake();
  }
  /** Public wake-ups for the session layer. */
  interrupt() { this.resetFlag = true; this.#wake(); }
  remoteEnded() { this.remoteFin = true; this.#wake(); }
  #wake() {
    const waiters = this.readWaiters.splice(0);
    for (const wake of waiters) wake();
  }
  consumed(bytes) {
    this.uncredited += bytes;
    if (this.uncredited < 1024 * 1024 || this.remoteFin) return;
    const delta = this.uncredited;
    this.uncredited = 0;
    this.receiveWindow += delta;
    this.session.sendFrame({ type: YTYPE.windowUpdate, flags: 0, streamId: this.id, length: delta });
  }
  /** Read exactly n bytes (or fewer at FIN). Resolves null at clean EOF with nothing buffered. */
  async read(n) {
    while (this.totalBuffered() < n && !this.remoteFin && !this.resetFlag) {
      await new Promise((resolve) => this.readWaiters.push(resolve));
    }
    if (this.totalBuffered() === 0) return null;
    const take = Math.min(n, this.totalBuffered());
    const out = Buffer.alloc(take);
    let written = 0;
    while (written < take) {
      const head = this.readBuffer[0];
      const need = take - written;
      if (head.length <= need) {
        head.copy(out, written);
        written += head.length;
        this.readBuffer.shift();
      } else {
        head.copy(out, written, 0, need);
        this.readBuffer[0] = head.subarray(need);
        written += need;
      }
    }
    this.consumed(take);
    return out;
  }
  /** Read until FIN (or maxBytes). */
  async readAll(maxBytes = 16 * 1024 * 1024) {
    const chunks = [];
    let total = 0;
    for (;;) {
      const chunk = await this.read(65536);
      if (chunk === null) break;
      chunks.push(chunk);
      total += chunk.length;
      if (total > maxBytes) throw new Error("response_too_large");
      if (this.remoteFin && this.totalBuffered() === 0) break;
    }
    return Buffer.concat(chunks);
  }
  totalBuffered() { return this.readBuffer.reduce((sum, b) => sum + b.length, 0); }
  waitAccepted() {
    if (this.established) return Promise.resolve();
    return new Promise((resolve) => this.acceptWaiters.push(resolve));
  }
}

// ---------------------------------------------------------------------------
// Session: WebSocket transport + handshake + records + mux + keepalive
export class RelaySession {
  constructor(socket, keys) {
    this.socket = socket;
    this.keys = keys;
    this.streams = new Map();
    this.highestId = 0;
    this.closed = false;
    this.closeCode = null;
    this.removed = false;
    this.pingCounter = 0;
    this.awaitingPong = null;
    this.pongTimer = null;
    this.pingTimer = setInterval(() => this.#ping(), 20000);
    this.pingTimer.unref?.();
  }
  static async dial({ url, transportByte, remoteStatic, psk, app, relay }) {
    const relayed = Boolean(relay);
    const socket = new WebSocket(url, [relayed ? "omb-relay.v1" : "omb-e2e.v1"]);
    socket.binaryType = "arraybuffer";
    return await new Promise((resolve, reject) => {
      let session = null;
      let hello = null;
      let connText = null;
      const deadline = setTimeout(() => reject(new Error("handshake deadline")), 20000);
      socket.onopen = () => {
        if (!relay) return begin();
        socket.send(JSON.stringify({ t: "phone", v: 1, hid: b64u(relay.hostId), adm: b64u(relay.adm) }));
      };
      const begin = () => {
        const conn = randomBytes(16);
        connText = b64u(conn);
        hello = phoneHello(
          { remoteStatic, psk, transport: transportByte },
          encodePayload1(conn, app),
          connText,
        );
        socket.send(hello.message1);
      };
      socket.onmessage = (event) => {
        const binary = typeof event.data !== "string";
        if (session) {
          if (!binary) { session.close(4000); return; }
          session.receiveRecord(new Uint8Array(event.data));
          return;
        }
        if (hello) {
          if (!binary) { clearTimeout(deadline); reject(new Error("expected binary message 2")); return; }
          try {
            const keys = hello.finish(new Uint8Array(event.data));
            session = new RelaySession(socket, keys);
            clearTimeout(deadline);
            resolve(session);
          } catch (error) {
            clearTimeout(deadline);
            reject(error);
          }
          return;
        }
        // Before the handshake: only the relay's ready.
        try {
          const parsed = JSON.parse(String(event.data));
          if (!binary && parsed.t === "ready") return begin();
        } catch { /* fall through */ }
        clearTimeout(deadline);
        reject(new Error("expected relay ready"));
      };
      socket.onclose = (event) => {
        clearTimeout(deadline);
        if (session) session.transportClosed(event.code);
        else reject(new Error(`socket closed during handshake (${event.code})`));
      };
      socket.onerror = () => {};
    });
  }
  transportClosed(code) {
    this.closeCode = code;
    this.#teardown();
  }
  close(code = 1000) {
    try { this.socket.close(code); } catch { /* already gone */ }
    this.#teardown();
  }
  #teardown() {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.pingTimer);
    if (this.pongTimer) clearTimeout(this.pongTimer);
    for (const stream of this.streams.values()) stream.interrupt();
  }
  #ping() {
    if (this.closed || this.awaitingPong !== null) return;
    this.pingCounter = (this.pingCounter + 1) >>> 0;
    this.awaitingPong = this.pingCounter;
    this.sendFrame({ type: YTYPE.ping, flags: YFLAG.syn, streamId: 0, length: this.pingCounter });
    this.pongTimer = setTimeout(() => this.close(1001), 10000);
    this.pongTimer.unref?.();
  }
  sendFrame(frame) {
    if (this.closed) return;
    const record = this.keys.send.seal(encodeFrame(frame));
    this.socket.send(record);
  }
  receiveRecord(record) {
    let plaintext;
    try {
      plaintext = this.keys.receive.open(record);
    } catch {
      return this.close(4000);
    }
    let frame;
    try {
      frame = decodeFrame(plaintext);
    } catch {
      return this.close(4000);
    }
    this.#receiveFrame(frame);
  }
  #receiveFrame(frame) {
    if (frame.type === YTYPE.ping) {
      if (frame.flags === YFLAG.syn) {
        this.sendFrame({ type: YTYPE.ping, flags: YFLAG.ack, streamId: 0, length: frame.length });
      } else if (frame.length === this.awaitingPong) {
        this.awaitingPong = null;
        if (this.pongTimer) clearTimeout(this.pongTimer);
      }
      return;
    }
    if (frame.type === YTYPE.goAway) {
      if (frame.length === 3) this.removed = true;
      else if (frame.length !== 0) this.close(4000);
      return;
    }
    const stream = this.streams.get(frame.streamId);
    if (frame.flags & YFLAG.ack) {
      if (!stream) return;
      stream.established = true;
      for (const wake of stream.acceptWaiters.splice(0)) wake();
      if (frame.type === YTYPE.windowUpdate && frame.length > 0) {
        stream.sendWindow += frame.length;
        stream.onWritable();
      }
      if (frame.flags & YFLAG.fin) this.#remoteFin(stream);
      return;
    }
    if (!stream) return;
    if (frame.flags & YFLAG.rst) {
      stream.interrupt();
      this.streams.delete(frame.streamId);
      return;
    }
    if (frame.type === YTYPE.data) {
      if (frame.length > stream.receiveWindow) return this.close(4000);
      stream.deliver(frame.data);
      if (frame.flags & YFLAG.fin) this.#remoteFin(stream);
    } else if (frame.type === YTYPE.windowUpdate) {
      if (frame.length > 0) {
        stream.sendWindow += frame.length;
        stream.onWritable();
      }
      if (frame.flags & YFLAG.fin) this.#remoteFin(stream);
    }
  }
  #remoteFin(stream) {
    stream.remoteEnded();
  }
  openStream() {
    if (this.closed) throw new Error("session closed");
    const id = this.highestId === 0 ? 1 : this.highestId + 2;
    this.highestId = id;
    const stream = new MuxStream(this, id);
    this.streams.set(id, stream);
    this.sendFrame({ type: YTYPE.windowUpdate, flags: YFLAG.syn, streamId: id, length: OPEN_DELTA });
    return stream;
  }
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 client over one mux stream (one request per stream).
export async function httpOverStream(session, { method = "GET", path, headers = {}, body = null, timeoutMs = 30000 }) {
  const stream = session.openStream();
  const lines = [`${method} ${path} HTTP/1.1`, "Host: e2e.invalid", "Connection: close"];
  const finalHeaders = { ...headers };
  let bodyBytes = null;
  if (body !== null) {
    bodyBytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
    finalHeaders["Content-Length"] = String(bodyBytes.length);
  }
  for (const [name, value] of Object.entries(finalHeaders)) lines.push(`${name}: ${value}`);
  const head = Buffer.from(lines.join("\r\n") + "\r\n\r\n", "utf8");
  await stream.write(bodyBytes ? Buffer.concat([head, bodyBytes]) : head);
  // No FIN here: the computer side drops a request whose FIN lands before its
  // origin pipe is up (seen live). Content-Length frames the request and
  // "Connection: close" ends it from the server's side.

  const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("http timeout")), timeoutMs));
  const readResponse = async () => {
    // Read the head first, byte by byte is wasteful; read chunks until \r\n\r\n.
    let buffer = Buffer.alloc(0);
    let headEnd = -1;
    while (headEnd < 0) {
      const chunk = await stream.read(8192);
      if (chunk === null) throw new Error("stream closed before response head");
      buffer = Buffer.concat([buffer, chunk]);
      headEnd = buffer.indexOf("\r\n\r\n");
    }
    const headText = buffer.subarray(0, headEnd).toString("utf8");
    let rest = buffer.subarray(headEnd + 4);
    const [statusLine, ...headerLines] = headText.split("\r\n");
    const status = Number(statusLine.split(" ")[1]);
    const responseHeaders = {};
    for (const line of headerLines) {
      const idx = line.indexOf(":");
      if (idx > 0) responseHeaders[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
    let responseBody;
    if ((responseHeaders["transfer-encoding"] ?? "").includes("chunked")) {
      const chunks = [];
      let pending = rest;
      for (;;) {
        let lineEnd = pending.indexOf("\r\n");
        while (lineEnd < 0) {
          const more = await stream.read(8192);
          if (more === null) throw new Error("stream closed inside chunked body");
          pending = Buffer.concat([pending, more]);
          lineEnd = pending.indexOf("\r\n");
        }
        const size = parseInt(pending.subarray(0, lineEnd).toString("utf8").split(";")[0], 16);
        pending = pending.subarray(lineEnd + 2);
        if (size === 0) { responseBody = Buffer.concat(chunks); break; }
        while (pending.length < size + 2) {
          const more = await stream.read(8192);
          if (more === null) throw new Error("stream closed inside chunk");
          pending = Buffer.concat([pending, more]);
        }
        chunks.push(pending.subarray(0, size));
        pending = pending.subarray(size + 2);
      }
    } else if (responseHeaders["content-length"] !== undefined) {
      const size = Number(responseHeaders["content-length"]);
      const chunks = [rest];
      let have = rest.length;
      while (have < size) {
        const more = await stream.read(Math.min(65536, size - have));
        if (more === null) break;
        chunks.push(more);
        have += more.length;
      }
      responseBody = Buffer.concat(chunks).subarray(0, size);
    } else {
      const chunks = [rest];
      for (;;) {
        const more = await stream.read(65536);
        if (more === null) break;
        chunks.push(more);
        if (stream.remoteFin && stream.totalBuffered() === 0) break;
      }
      responseBody = Buffer.concat(chunks);
    }
    return { status, headers: responseHeaders, body: responseBody };
  };
  try {
    return await Promise.race([readResponse(), timeout]);
  } finally {
    try { stream.end(); } catch { /* session may already be closed */ }
    session.streams.delete(stream.id);
  }
}
