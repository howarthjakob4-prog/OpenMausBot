import com.ferrum.mausbot.E2e;
import com.ferrum.mausbot.RelaySession;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates the Java port (E2e + RelaySession frame codec) against the wire
 * spec's published test vectors — the same checks tools/test-vectors.mjs runs
 * for the JS reference, phone side. Run:
 *   javac -d /tmp/e2e-test -cp android-src/src tools/java-test/TestE2e.java ...
 * (see tools/java-test/run.sh)
 */
public class TestE2e {
    static int passed = 0, failed = 0;

    static void check(String name, boolean ok) {
        if (ok) { passed++; System.out.println("PASS " + name); }
        else { failed++; System.out.println("FAIL " + name); }
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    // --- tiny JSON parser (test code only) --------------------------------
    static final class Json {
        private final String s;
        private int i;

        Json(String s) { this.s = s; }

        Object parse() { Object v = value(); return v; }

        private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }

        private Object value() {
            ws();
            char c = s.charAt(i);
            if (c == '{') {
                i++;
                Map<String, Object> map = new LinkedHashMap<>();
                ws();
                if (s.charAt(i) == '}') { i++; return map; }
                while (true) {
                    ws();
                    String key = (String) value();
                    ws();
                    if (s.charAt(i) != ':') throw new IllegalStateException("expected :");
                    i++;
                    map.put(key, value());
                    ws();
                    char d = s.charAt(i++);
                    if (d == '}') break;
                    if (d != ',') throw new IllegalStateException("expected ,");
                }
                return map;
            }
            if (c == '[') {
                i++;
                List<Object> list = new ArrayList<>();
                ws();
                if (s.charAt(i) == ']') { i++; return list; }
                while (true) {
                    list.add(value());
                    ws();
                    char d = s.charAt(i++);
                    if (d == ']') break;
                    if (d != ',') throw new IllegalStateException("expected ,");
                }
                return list;
            }
            if (c == '"') {
                i++;
                StringBuilder out = new StringBuilder();
                while (true) {
                    char ch = s.charAt(i++);
                    if (ch == '"') break;
                    if (ch == '\\') {
                        char esc = s.charAt(i++);
                        switch (esc) {
                            case 'n': out.append('\n'); break;
                            case 't': out.append('\t'); break;
                            case 'r': out.append('\r'); break;
                            case 'u':
                                out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                                i += 4;
                                break;
                            default: out.append(esc);
                        }
                    } else {
                        out.append(ch);
                    }
                }
                return out.toString();
            }
            int start = i;
            while (i < s.length() && ",}] \t\r\n".indexOf(s.charAt(i)) < 0) i++;
            String tok = s.substring(start, i);
            if (tok.equals("true")) return Boolean.TRUE;
            if (tok.equals("false")) return Boolean.FALSE;
            if (tok.equals("null")) return null;
            return Double.parseDouble(tok);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) { return (List<Object>) o; }

    static String str(Object o) { return (String) o; }

    static int num(Object o) { return ((Double) o).intValue(); }

    public static void main(String[] args) throws Exception {
        String path = args[0];
        Map<String, Object> v = obj(new Json(new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8)).parse());
        Map<String, Object> inputs = obj(v.get("inputs"));

        // ---- V1: identities and derivations
        Map<String, Object> v1 = obj(v.get("V1"));
        E2e.KeyPairBytes transport = E2e.keyPairFromPrivate(hex(str(inputs.get("transportPrivate"))));
        check("V1 transportPublic", Arrays.equals(transport.publicKey, hex(str(v1.get("transportPublic")))));
        byte[] keyId = E2e.keyIdOf(transport.publicKey);
        check("V1 keyId", Arrays.equals(keyId, hex(str(v1.get("keyId")))));
        byte[] hostId = hex(str(inputs.get("hostId")));
        for (Object o : arr(v1.get("credentials"))) {
            Map<String, Object> want = obj(o);
            String label = str(want.get("name"));
            byte[] credHash = E2e.credentialHash(str(want.get("token")));
            check("V1 " + label + " credHash", Arrays.equals(credHash, hex(str(want.get("credHash")))));
            check("V1 " + label + " psk", Arrays.equals(E2e.pskFor(credHash, keyId), hex(str(want.get("psk")))));
            check("V1 " + label + " adm", Arrays.equals(E2e.admissionFor(credHash, hostId), hex(str(want.get("adm")))));
        }
        E2e.KeyPairBytes phoneEph = E2e.keyPairFromPrivate(hex(str(inputs.get("phoneEphemeralPrivate"))));
        E2e.KeyPairBytes computerEph = E2e.keyPairFromPrivate(hex(str(inputs.get("computerEphemeralPrivate"))));
        check("V1 phone ephemeral public", Arrays.equals(phoneEph.publicKey, hex(str(v1.get("phoneEphemeralPublic")))));
        check("V1 computer ephemeral public", Arrays.equals(computerEph.publicKey, hex(str(v1.get("computerEphemeralPublic")))));
        Map<String, Object> dhv = obj(v1.get("dh"));
        check("V1 dh es", Arrays.equals(E2e.dh(hex(str(inputs.get("transportPrivate"))), phoneEph.publicKey), hex(str(dhv.get("es")))));
        check("V1 dh ee", Arrays.equals(E2e.dh(hex(str(inputs.get("phoneEphemeralPrivate"))), computerEph.publicKey), hex(str(dhv.get("ee")))));

        // ---- V2: handshake (phone side; message2 comes from the vectors)
        Map<String, Object> v2 = obj(v.get("V2"));
        byte[] devicePsk = E2e.pskFor(E2e.credentialHash(str(inputs.get("deviceToken"))), keyId);
        byte[] payload1 = str(inputs.get("payload1")).getBytes(StandardCharsets.UTF_8);
        E2e.PhoneHello hello = E2e.phoneHello(transport.publicKey, devicePsk, 1, phoneEph, payload1, str(inputs.get("connB64u")));
        check("V2 message1", Arrays.equals(hello.message1, hex(str(v2.get("message1")))));
        E2e.SessionKeys keys = hello.finish(hex(str(v2.get("message2"))));
        check("V2 phone kPc", Arrays.equals(keys.kPc, hex(str(v2.get("kPc")))));
        check("V2 phone kCp", Arrays.equals(keys.kCp, hex(str(v2.get("kCp")))));
        check("V2 phone handshakeHash", Arrays.equals(keys.handshakeHash, hex(str(v2.get("handshakeHash")))));

        // ---- V4: transport records of the V2 session
        Map<String, Object> v4 = obj(v.get("V4"));
        for (Object o : arr(v4.get("records"))) {
            Map<String, Object> record = obj(o);
            byte[] frame = hex(str(record.get("frame")));
            if ("pc".equals(str(record.get("direction")))) {
                check("V4 pc record n=" + num(record.get("n")),
                        Arrays.equals(keys.send.seal(frame), hex(str(record.get("record")))));
            } else {
                check("V4 cp record n=" + num(record.get("n")) + " opens",
                        Arrays.equals(keys.receive.open(hex(str(record.get("record")))), frame));
            }
        }

        // ---- V5: yamux frames byte for byte
        for (Object o : arr(v.get("V5"))) {
            Map<String, Object> item = obj(o);
            byte[] want = hex(str(item.get("hex")));
            int type = num(item.get("type"));
            byte[] data = type == 0 ? Arrays.copyOfRange(want, 12, want.length) : null;
            byte[] got = RelaySession.encodeFrame(type, num(item.get("flags")),
                    num(item.get("streamId")), num(item.get("length")), data);
            check("V5 " + str(item.get("name")), Arrays.equals(got, want));
        }

        System.out.println("\n" + passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }
}
