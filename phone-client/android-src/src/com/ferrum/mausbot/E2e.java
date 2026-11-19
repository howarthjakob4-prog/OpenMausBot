package com.ferrum.mausbot;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The OpenMausBot E2E phone wire protocol (wire spec v1), implemented from the
 * published spec in Jakob's fork of OpenMausBot (Apache-2.0) — the Java twin of
 * tools/relay-lib.mjs, which is verified against the spec's test vectors and
 * proven live against the real server. This class covers the credential
 * derivations, the Noise_NKpsk0_P256_AESGCM_SHA256 initiator handshake, and the
 * AEAD record layer. Verified against vectors/v1.json by tools/java-test.
 */
public final class E2e {
    private E2e() {}

    public static final String PROTOCOL_NAME = "Noise_NKpsk0_P256_AESGCM_SHA256";
    public static final int TRANSPORT_RELAY = 0x01;
    public static final int TRANSPORT_DIRECT = 0x02;
    private static final int TAG = 16;
    private static final SecureRandom RNG = new SecureRandom();

    // ------------------------------------------------------------------
    // base64url, strict (canonical, unpadded)
    private static final String B64_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    public static String b64u(byte[] bytes) {
        StringBuilder out = new StringBuilder((bytes.length + 2) / 3 * 4);
        int i = 0;
        while (i + 3 <= bytes.length) {
            int v = ((bytes[i] & 0xff) << 16) | ((bytes[i + 1] & 0xff) << 8) | (bytes[i + 2] & 0xff);
            out.append(B64_ALPHABET.charAt((v >>> 18) & 63));
            out.append(B64_ALPHABET.charAt((v >>> 12) & 63));
            out.append(B64_ALPHABET.charAt((v >>> 6) & 63));
            out.append(B64_ALPHABET.charAt(v & 63));
            i += 3;
        }
        int rem = bytes.length - i;
        if (rem == 1) {
            int v = (bytes[i] & 0xff) << 16;
            out.append(B64_ALPHABET.charAt((v >>> 18) & 63));
            out.append(B64_ALPHABET.charAt((v >>> 12) & 63));
        } else if (rem == 2) {
            int v = ((bytes[i] & 0xff) << 16) | ((bytes[i + 1] & 0xff) << 8);
            out.append(B64_ALPHABET.charAt((v >>> 18) & 63));
            out.append(B64_ALPHABET.charAt((v >>> 12) & 63));
            out.append(B64_ALPHABET.charAt((v >>> 6) & 63));
        }
        return out.toString();
    }

    /** Strict decode: canonical alphabet, no padding, re-encode must match. */
    public static byte[] fromB64u(String text) {
        if (text == null) return null;
        int len = text.length();
        if (len % 4 == 1) return null;
        for (int i = 0; i < len; i++) {
            if (B64_ALPHABET.indexOf(text.charAt(i)) < 0) return null;
        }
        int full = len / 4;
        int rem = len % 4;
        byte[] out = new byte[full * 3 + (rem == 0 ? 0 : rem - 1)];
        int o = 0;
        for (int g = 0; g < full; g++) {
            int v = 0;
            for (int k = 0; k < 4; k++) v = (v << 6) | B64_ALPHABET.indexOf(text.charAt(g * 4 + k));
            out[o++] = (byte) (v >>> 16);
            out[o++] = (byte) (v >>> 8);
            out[o++] = (byte) v;
        }
        if (rem == 2) {
            int v = (B64_ALPHABET.indexOf(text.charAt(len - 2)) << 6)
                    | B64_ALPHABET.indexOf(text.charAt(len - 1));
            out[o] = (byte) (v >>> 4);
        } else if (rem == 3) {
            int v = (B64_ALPHABET.indexOf(text.charAt(len - 3)) << 12)
                    | (B64_ALPHABET.indexOf(text.charAt(len - 2)) << 6)
                    | B64_ALPHABET.indexOf(text.charAt(len - 1));
            out[o++] = (byte) (v >>> 10);
            out[o] = (byte) (v >>> 2);
        }
        if (!b64u(out).equals(text)) return null;
        return out;
    }

    // ------------------------------------------------------------------
    // Hashes
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(msg);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Credential derivations (spec section 2)
    public static byte[] credentialHash(String token) {
        return sha256(token.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] keyIdOf(byte[] transportPub) {
        return Arrays.copyOf(sha256(transportPub), 16);
    }

    public static byte[] pskFor(byte[] credHash, byte[] keyId) {
        return hmacSha256(credHash, concat("omb-e2e psk v1".getBytes(StandardCharsets.UTF_8), keyId));
    }

    public static byte[] admissionFor(byte[] credHash, byte[] hostId) {
        return hmacSha256(credHash, concat("omb-relay admission v1".getBytes(StandardCharsets.UTF_8), hostId));
    }

    // ------------------------------------------------------------------
    // Pairing link parsing (spec section 3)
    public static final class PairingLink {
        public String token;
        public String name = "";
        public byte[] transportPub;
        public byte[] hostId; // null for direct links
        public List<String> relays = new ArrayList<>();
    }

    public static PairingLink parsePairingLink(String link) throws Exception {
        if (link == null) throw new Exception("empty link");
        String trimmed = link.trim();
        if (!trimmed.startsWith("openmausbot://")) throw new Exception("not an openmausbot link");
        String token = queryParam(trimmed, "token");
        String name = queryParam(trimmed, "name");
        String e2eRaw = queryParam(trimmed, "e2e");
        if (token == null || token.isEmpty()) throw new Exception("pairing link has no token");
        if (e2eRaw == null) throw new Exception("pairing link has no e2e descriptor");
        byte[] e2eBytes = fromB64u(e2eRaw);
        if (e2eBytes == null) throw new Exception("e2e descriptor is not strict base64url");
        String json = new String(e2eBytes, StandardCharsets.UTF_8);
        // The descriptor is a flat JSON object {v, k, h, r[]} — read it with
        // the tiny extractor below rather than a JSON library.
        String v = jsonValue(json, "v");
        if (v == null || !v.trim().equals("1")) throw new Exception("e2e version: update required");
        String k = jsonString(json, "k");
        byte[] transportPub = k == null ? null : fromB64u(k);
        if (transportPub == null || transportPub.length != 65 || transportPub[0] != 0x04) {
            throw new Exception("e2e descriptor has a bad transport key");
        }
        String h = jsonString(json, "h");
        byte[] hostId = h == null ? null : fromB64u(h);
        List<String> relays = jsonStringArray(json, "r");
        if (hostId != null && relays.isEmpty()) throw new Exception("e2e descriptor: h and r must come together");
        if (hostId == null && !relays.isEmpty()) throw new Exception("e2e descriptor: h and r must come together");
        for (String host : relays) {
            if (!host.matches("^relay[1-9][0-9]?\\.openmausbot\\.com$")) {
                throw new Exception("relay host not allowed: " + host);
            }
        }
        if (hostId != null && hostId.length != 16) throw new Exception("e2e descriptor has a bad hostId");
        PairingLink out = new PairingLink();
        out.token = token;
        out.name = name == null ? "" : name;
        out.transportPub = transportPub;
        out.hostId = hostId;
        out.relays = relays;
        return out;
    }

    private static String queryParam(String url, String key) {
        int q = url.indexOf('?');
        if (q < 0) return null;
        String query = url.substring(q + 1);
        int hash = query.indexOf('#');
        if (hash >= 0) query = query.substring(0, hash);
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            if (pair.substring(0, eq).equals(key)) return urlDecode(pair.substring(eq + 1));
        }
        return null;
    }

    private static String urlDecode(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                out.append((char) Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 2;
            } else if (c == '+') {
                out.append(' ');
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** Value of a top-level "key": <number-or-bare-token> in a flat JSON object. */
    private static String jsonValue(String json, String key) {
        int i = json.indexOf("\"" + key + "\"");
        if (i < 0) return null;
        int colon = json.indexOf(':', i + key.length() + 2);
        if (colon < 0) return null;
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        int end = start;
        while (end < json.length() && ",}]".indexOf(json.charAt(end)) < 0) end++;
        return json.substring(start, end).trim();
    }

    private static String jsonString(String json, String key) {
        int i = json.indexOf("\"" + key + "\"");
        if (i < 0) return null;
        int colon = json.indexOf(':', i + key.length() + 2);
        if (colon < 0) return null;
        int start = json.indexOf('"', colon);
        if (start < 0) return null;
        StringBuilder out = new StringBuilder();
        for (int p = start + 1; p < json.length(); p++) {
            char c = json.charAt(p);
            if (c == '\\' && p + 1 < json.length()) {
                out.append(json.charAt(++p));
            } else if (c == '"') {
                return out.toString();
            } else {
                out.append(c);
            }
        }
        return null;
    }

    private static List<String> jsonStringArray(String json, String key) {
        List<String> out = new ArrayList<>();
        int i = json.indexOf("\"" + key + "\"");
        if (i < 0) return out;
        int open = json.indexOf('[', i);
        int close = open < 0 ? -1 : json.indexOf(']', open);
        if (open < 0 || close < 0) return out;
        String body = json.substring(open + 1, close);
        int p = 0;
        while (true) {
            int s = body.indexOf('"', p);
            if (s < 0) break;
            int e = body.indexOf('"', s + 1);
            if (e < 0) break;
            out.add(body.substring(s + 1, e));
            p = e + 1;
        }
        return out;
    }

    // ------------------------------------------------------------------
    // P-256 via JCA. Public-from-private uses hand-rolled point math
    // (JCA has no point-multiplication API); DH uses KeyAgreement.
    private static final BigInteger P =
            new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger A = P.subtract(BigInteger.valueOf(3));
    private static final BigInteger B =
            new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger GX =
            new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    private static final BigInteger GY =
            new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);

    private static ECParameterSpec ecSpec() {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec("secp256r1"));
            return ap.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ECPoint pointAdd(ECPoint p1, ECPoint p2) {
        if (p1 == null) return p2;
        if (p2 == null) return p1;
        BigInteger x1 = p1.getAffineX(), y1 = p1.getAffineY();
        BigInteger x2 = p2.getAffineX(), y2 = p2.getAffineY();
        BigInteger slope;
        if (x1.equals(x2)) {
            if (!y1.equals(y2) || y1.signum() == 0) return null; // infinity
            // doubling: slope = (3x^2 + a) / 2y
            slope = x1.multiply(x1).multiply(BigInteger.valueOf(3)).add(A)
                    .multiply(y1.shiftLeft(1).modInverse(P)).mod(P);
        } else {
            slope = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(P)).mod(P);
        }
        BigInteger x3 = slope.multiply(slope).subtract(x1).subtract(x2).mod(P);
        BigInteger y3 = slope.multiply(x1.subtract(x3)).subtract(y1).mod(P);
        return new ECPoint(x3, y3);
    }

    private static ECPoint pointMul(BigInteger k, ECPoint point) {
        ECPoint result = null;
        ECPoint addend = point;
        BigInteger scalar = k;
        while (scalar.signum() > 0) {
            if (scalar.testBit(0)) result = pointAdd(result, addend);
            addend = pointAdd(addend, addend);
            scalar = scalar.shiftRight(1);
        }
        return result;
    }

    private static byte[] bigTo32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int srcPos = Math.max(0, raw.length - 32);
        int len = Math.min(32, raw.length);
        System.arraycopy(raw, srcPos, out, 32 - len, len);
        return out;
    }

    public static byte[] encodePoint(ECPoint point) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(bigTo32(point.getAffineX()), 0, out, 1, 32);
        System.arraycopy(bigTo32(point.getAffineY()), 0, out, 33, 32);
        return out;
    }

    private static ECPoint decodePoint(byte[] pub) throws Exception {
        if (pub.length != 65 || pub[0] != 0x04) throw new Exception("bad_point");
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(pub, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(pub, 33, 65));
        if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) throw new Exception("bad_point");
        // y^2 == x^3 + a x + b (mod p)
        BigInteger lhs = y.multiply(y).mod(P);
        BigInteger rhs = x.multiply(x).multiply(x).add(A.multiply(x)).add(B).mod(P);
        if (!lhs.equals(rhs)) throw new Exception("bad_point");
        return new ECPoint(x, y);
    }

    /** A P-256 key pair: 32-byte private scalar + 65-byte uncompressed public. */
    public static final class KeyPairBytes {
        public final byte[] privateKey;
        public final byte[] publicKey;

        KeyPairBytes(byte[] priv, byte[] pub) {
            this.privateKey = priv;
            this.publicKey = pub;
        }
    }

    public static KeyPairBytes generateKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"), RNG);
            KeyPair kp = gen.generateKeyPair();
            BigInteger s = ((ECPrivateKey) kp.getPrivate()).getS();
            ECPoint w = ((ECPublicKey) kp.getPublic()).getW();
            return new KeyPairBytes(bigTo32(s), encodePoint(w));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPairBytes keyPairFromPrivate(byte[] privateKey) {
        BigInteger s = new BigInteger(1, privateKey);
        ECPoint w = pointMul(s, new ECPoint(GX, GY));
        return new KeyPairBytes(bigTo32(s), encodePoint(w));
    }

    public static byte[] dh(byte[] privateKey, byte[] publicKey) throws Exception {
        ECPoint w = decodePoint(publicKey);
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPublicKey pub = (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(w, ecSpec()));
        ECPrivateKey priv = (ECPrivateKey) kf.generatePrivate(
                new ECPrivateKeySpec(new BigInteger(1, privateKey), ecSpec()));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(pub, true);
        byte[] secret = ka.generateSecret();
        if (secret.length == 32) return secret;
        if (secret.length > 32) {
            // strip leading zero bytes down to the 32-byte X coordinate
            int off = secret.length - 32;
            for (int i = 0; i < off; i++) if (secret[i] != 0) throw new Exception("bad_secret");
            return Arrays.copyOfRange(secret, off, secret.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(secret, 0, out, 32 - secret.length, secret.length);
        return out;
    }

    // ------------------------------------------------------------------
    // Noise symmetric state
    private static byte[][] hkdf(byte[] ck, byte[] ikm, int outputs) {
        byte[] temp = hmacSha256(ck, ikm);
        byte[][] out = new byte[outputs][];
        byte[] prev = new byte[0];
        for (int i = 0; i < outputs; i++) {
            prev = hmacSha256(temp, concat(prev, new byte[]{(byte) (i + 1)}));
            out[i] = prev;
        }
        return out;
    }

    private static byte[] nonceBytes(long n) {
        byte[] nonce = new byte[12];
        for (int i = 0; i < 8; i++) nonce[11 - i] = (byte) (n >>> (8 * i));
        return nonce;
    }

    private static byte[] aeadSeal(byte[] key, long n, byte[] ad, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG * 8, nonceBytes(n)));
        if (ad.length > 0) cipher.updateAAD(ad);
        return cipher.doFinal(plaintext); // ciphertext || tag
    }

    private static byte[] aeadOpen(byte[] key, long n, byte[] ad, byte[] ciphertext) throws Exception {
        if (ciphertext.length < TAG) throw new Exception("short_ciphertext");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG * 8, nonceBytes(n)));
        if (ad.length > 0) cipher.updateAAD(ad);
        return cipher.doFinal(ciphertext);
    }

    static final class CipherState {
        byte[] key; // null = unkeyed (plaintext passthrough)
        long n;

        CipherState() {}

        CipherState(byte[] key) {
            this.key = key;
        }

        byte[] encryptWithAd(byte[] ad, byte[] plaintext) throws Exception {
            if (key == null) return plaintext.clone();
            byte[] out = aeadSeal(key, n, ad, plaintext);
            n += 1;
            return out;
        }

        byte[] decryptWithAd(byte[] ad, byte[] ciphertext) throws Exception {
            if (key == null) return ciphertext.clone();
            byte[] out = aeadOpen(key, n, ad, ciphertext);
            n += 1;
            return out;
        }
    }

    static final class SymmetricState {
        byte[] h;
        byte[] ck;
        CipherState cipher = new CipherState();

        static SymmetricState initialize() {
            byte[] name = PROTOCOL_NAME.getBytes(StandardCharsets.UTF_8);
            byte[] h;
            if (name.length <= 32) {
                h = new byte[32];
                System.arraycopy(name, 0, h, 0, name.length);
            } else {
                h = sha256(name);
            }
            SymmetricState s = new SymmetricState();
            s.h = h;
            s.ck = h.clone();
            return s;
        }

        void mixHash(byte[] data) {
            h = sha256(concat(h, data));
        }

        void mixKey(byte[] ikm) {
            byte[][] parts = hkdf(ck, ikm, 2);
            ck = parts[0];
            cipher = new CipherState(parts[1]);
        }

        void mixKeyAndHash(byte[] ikm) {
            byte[][] parts = hkdf(ck, ikm, 3);
            ck = parts[0];
            mixHash(parts[1]);
            cipher = new CipherState(parts[2]);
        }

        byte[] encryptAndHash(byte[] plaintext) throws Exception {
            byte[] out = cipher.encryptWithAd(h, plaintext);
            mixHash(out);
            return out;
        }

        byte[] decryptAndHash(byte[] ciphertext) throws Exception {
            byte[] out = cipher.decryptWithAd(h, ciphertext);
            mixHash(ciphertext);
            return out;
        }

        CipherState[] split() {
            byte[][] parts = hkdf(ck, new byte[0], 2);
            return new CipherState[]{new CipherState(parts[0]), new CipherState(parts[1])};
        }
    }

    public static byte[] prologue(int transport) {
        return concat("omb-e2e/1".getBytes(StandardCharsets.UTF_8),
                new byte[]{0x00, (byte) transport});
    }

    private static SymmetricState initialized(int transport, byte[] responderStatic) {
        SymmetricState state = SymmetricState.initialize();
        state.mixHash(prologue(transport));
        state.mixHash(responderStatic);
        return state;
    }

    // ------------------------------------------------------------------
    // Records
    public static final class RecordCipher {
        private final CipherState state;

        public RecordCipher(CipherState state) {
            this.state = state;
        }

        public byte[] seal(byte[] plaintext) throws Exception {
            if (plaintext.length > 65535 - TAG) throw new Exception("record_too_large");
            return state.encryptWithAd(new byte[0], plaintext);
        }

        public byte[] open(byte[] record) throws Exception {
            if (record.length > 65535) throw new Exception("record_too_large");
            return state.decryptWithAd(new byte[0], record);
        }
    }

    public static final class SessionKeys {
        public RecordCipher send;
        public RecordCipher receive;
        public byte[] handshakeHash;
        public byte[] kPc;
        public byte[] kCp;
    }

    private static SessionKeys sessionKeys(SymmetricState state) {
        CipherState[] pair = state.split();
        SessionKeys keys = new SessionKeys();
        keys.send = new RecordCipher(pair[0]); // phone -> computer
        keys.receive = new RecordCipher(pair[1]); // computer -> phone
        keys.handshakeHash = state.h;
        keys.kPc = pair[0].key;
        keys.kCp = pair[1].key;
        return keys;
    }

    public static byte[] encodePayload1(byte[] connBytes, String app) {
        String json = "{\"v\":1,\"conn\":\"" + b64u(connBytes) + "\",\"app\":\"" + app + "\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    /** Initiator handshake: build message 1 now, finish with message 2 later. */
    public static final class PhoneHello {
        public final byte[] message1;
        private final SymmetricState state;
        private final KeyPairBytes ephemeral;
        private final String connText;
        private boolean done;

        private PhoneHello(byte[] message1, SymmetricState state, KeyPairBytes ephemeral, String connText) {
            this.message1 = message1;
            this.state = state;
            this.ephemeral = ephemeral;
            this.connText = connText;
        }

        public SessionKeys finish(byte[] message2) throws Exception {
            if (done) throw new Exception("finished");
            done = true;
            if (message2.length < 65 + TAG || message2.length > 65 + 512 + TAG) {
                throw new Exception("message2_size");
            }
            byte[] re = Arrays.copyOfRange(message2, 0, 65);
            byte[] ee = dh(ephemeral.privateKey, re);
            state.mixHash(re);
            state.mixKey(re);
            state.mixKey(ee);
            byte[] payload2 = state.decryptAndHash(Arrays.copyOfRange(message2, 65, message2.length));
            String json = new String(payload2, StandardCharsets.UTF_8);
            String v = jsonValue(json, "v");
            if (v == null || !v.trim().equals("1")) throw new Exception("payload2_version");
            String conn = jsonString(json, "conn");
            if (conn == null || !conn.equals(connText)) throw new Exception("payload2_conn");
            return sessionKeys(state);
        }
    }

    public static PhoneHello phoneHello(byte[] remoteStatic, byte[] psk, int transport,
                                        KeyPairBytes ephemeral, byte[] payload1, String connText)
            throws Exception {
        if (psk.length != 32) throw new Exception("bad_psk");
        if (payload1.length > 512) throw new Exception("payload_too_large");
        SymmetricState state = initialized(transport, remoteStatic);
        state.mixKeyAndHash(psk);
        KeyPairBytes e = ephemeral != null ? ephemeral : generateKeyPair();
        state.mixHash(e.publicKey);
        state.mixKey(e.publicKey);
        state.mixKey(dh(e.privateKey, remoteStatic));
        byte[] message1 = concat(e.publicKey, state.encryptAndHash(payload1));
        return new PhoneHello(message1, state, e, connText);
    }

    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        RNG.nextBytes(out);
        return out;
    }
}
