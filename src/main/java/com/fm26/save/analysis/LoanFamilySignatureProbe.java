package com.fm26.save.analysis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class LoanFamilySignatureProbe {

    private static final int WINDOW_START = -1040;
    private static final int WINDOW_END = -860;

    private LoanFamilySignatureProbe() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("trauner_loan", new Scenario(Path.of("/tmp/trauner_loan_1009.bin"), 66_590_782));
        scenarios.put("smal_loan", new Scenario(Path.of("/tmp/smal_loan_1009.bin"), 67_761_950));
        scenarios.put("bos_changed", new Scenario(Path.of("/tmp/bos_1009.bin"), 69_660_694));
        scenarios.put("beelen_changed", new Scenario(Path.of("/tmp/beelen_1009.bin"), 67_999_409));
        scenarios.put("plug_changed", new Scenario(Path.of("/tmp/plug_1013.bin"), 70_081_303));
        scenarios.put("zechiel_changed", new Scenario(Path.of("/tmp/zechiel_1013.bin"), 69_862_677));

        StringBuilder out = new StringBuilder(32768);
        out.append("{\n");
        int i = 0;
        for (Map.Entry<String, Scenario> entry : scenarios.entrySet()) {
            byte[] payload = Files.readAllBytes(entry.getValue().payload());
            int pair = entry.getValue().personPair();
            out.append("  ").append(quote(entry.getKey())).append(": {\n");
            field(out, 4, "personPair", Integer.toString(pair), true);
            field(out, 4, "windowHex", quote(hex(payload, pair + WINDOW_START, WINDOW_END - WINDOW_START)), true);
            field(out, 4, "signature", renderSignature(payload, pair), false);
            out.append("  }");
            if (++i < scenarios.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("}\n");
        System.out.print(out);
    }

    private static String renderSignature(byte[] payload, int pair) {
        StringBuilder out = new StringBuilder("{");
        boolean first = true;

        first = append(out, first, "hasF0Run", Boolean.toString(hasRun(payload, pair + WINDOW_START, pair + WINDOW_END, (byte) 0xF0, 8)));
        first = append(out, first, "has6c07Marker", Boolean.toString(indexOfWord(payload, pair + WINDOW_START, pair + WINDOW_END, 0x076c) >= 0));
        first = append(out, first, "has010103", Boolean.toString(indexOfBytes(payload, pair + WINDOW_START, pair + WINDOW_END, new byte[]{0x01, 0x01, 0x03}) >= 0));
        first = append(out, first, "has0500Header", Boolean.toString(indexOfBytes(payload, pair + WINDOW_START, pair + WINDOW_END, new byte[]{0x05, 0x00}) >= 0));
        first = append(out, first, "firstF0RunRel", Integer.toString(relativeRun(payload, pair, (byte) 0xF0, 8)));
        first = append(out, first, "first6c07Rel", Integer.toString(relativeWord(payload, pair, 0x076c)));
        first = append(out, first, "first010103Rel", Integer.toString(relativeBytes(payload, pair, new byte[]{0x01, 0x01, 0x03})));
        first = append(out, first, "firstHeaderRel", Integer.toString(relativeBytes(payload, pair, new byte[]{0x05})));
        first = append(out, first, "candidateRows", renderCandidateRows(payload, pair));
        out.append("}");
        return out.toString();
    }

    private static String renderCandidateRows(byte[] payload, int pair) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (int rel = WINDOW_START; rel < WINDOW_END; rel += 4) {
            int off = pair + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            byte[] chunk = new byte[16];
            System.arraycopy(payload, off, chunk, 0, 16);
            if (!isInteresting(chunk)) {
                continue;
            }
            if (!first) {
                out.append(", ");
            }
            first = false;
            out.append("{\"rel\":").append(rel)
                    .append(",\"hex\":").append(quote(hex(chunk, 0, chunk.length)))
                    .append("}");
        }
        out.append("]");
        return out.toString();
    }

    private static boolean isInteresting(byte[] chunk) {
        int nonZero = 0;
        int f0 = 0;
        for (byte b : chunk) {
            if (b != 0) {
                nonZero++;
            }
            if ((b & 0xFF) == 0xF0) {
                f0++;
            }
        }
        if (f0 >= 4) {
            return true;
        }
        if (nonZero >= 8 && containsWord(chunk, 0x076c)) {
            return true;
        }
        return containsBytes(chunk, new byte[]{0x01, 0x01, 0x03});
    }

    private static boolean hasRun(byte[] payload, int start, int end, byte value, int minRun) {
        return relativeRun(payload, 0, value, minRun, start, end) >= 0;
    }

    private static int relativeRun(byte[] payload, int pair, byte value, int minRun) {
        return relativeRun(payload, pair, value, minRun, pair + WINDOW_START, pair + WINDOW_END);
    }

    private static int relativeRun(byte[] payload, int pair, byte value, int minRun, int start, int end) {
        int run = 0;
        for (int off = Math.max(0, start); off < Math.min(payload.length, end); off++) {
            if (payload[off] == value) {
                run++;
                if (run >= minRun) {
                    return off - run + 1 - pair;
                }
            } else {
                run = 0;
            }
        }
        return -1;
    }

    private static int relativeWord(byte[] payload, int pair, int word) {
        int hit = indexOfWord(payload, pair + WINDOW_START, pair + WINDOW_END, word);
        return hit < 0 ? -1 : hit - pair;
    }

    private static int indexOfWord(byte[] payload, int start, int end, int word) {
        for (int off = Math.max(0, start); off + 2 <= Math.min(payload.length, end); off++) {
            int value = (payload[off] & 0xFF) | ((payload[off + 1] & 0xFF) << 8);
            if (value == word) {
                return off;
            }
        }
        return -1;
    }

    private static boolean containsWord(byte[] payload, int word) {
        return indexOfWord(payload, 0, payload.length, word) >= 0;
    }

    private static int relativeBytes(byte[] payload, int pair, byte[] needle) {
        int hit = indexOfBytes(payload, pair + WINDOW_START, pair + WINDOW_END, needle);
        return hit < 0 ? -1 : hit - pair;
    }

    private static int indexOfBytes(byte[] payload, int start, int end, byte[] needle) {
        outer:
        for (int off = Math.max(0, start); off + needle.length <= Math.min(payload.length, end); off++) {
            for (int i = 0; i < needle.length; i++) {
                if (payload[off + i] != needle[i]) {
                    continue outer;
                }
            }
            return off;
        }
        return -1;
    }

    private static boolean containsBytes(byte[] payload, byte[] needle) {
        return indexOfBytes(payload, 0, payload.length, needle) >= 0;
    }

    private static String hex(byte[] payload, int offset, int length) {
        int start = Math.max(0, offset);
        int end = Math.min(payload.length, start + length);
        StringBuilder out = new StringBuilder((end - start) * 3);
        for (int i = start; i < end; i++) {
            if (i > start) {
                out.append(' ');
            }
            out.append(String.format(Locale.ROOT, "%02x", payload[i] & 0xFF));
        }
        return out.toString();
    }

    private static boolean append(StringBuilder out, boolean first, String key, String value) {
        if (!first) {
            out.append(", ");
        }
        out.append(quote(key)).append(": ").append(value);
        return false;
    }

    private static void field(StringBuilder out, int indent, String key, String value, boolean trailingComma) {
        out.append(" ".repeat(indent))
                .append(quote(key))
                .append(": ")
                .append(value);
        if (trailingComma) {
            out.append(',');
        }
        out.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record Scenario(Path payload, int personPair) {
    }
}
