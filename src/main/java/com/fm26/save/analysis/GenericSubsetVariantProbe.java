package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class GenericSubsetVariantProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;

    private static final LayoutVariant TRAUNER = new LayoutVariant(
            "trauner",
            Map.of(
                    "potential ability", new Spec(-1192 + 8, Enc.U16LE),
                    "striker", new Spec(-1160 + 10, Enc.U8),
                    "finishing", new Spec(-1145 + 0, Enc.TIMES5),
                    "pace", new Spec(-1145 + 36, Enc.TIMES5),
                    "concentration", new Spec(-1145 + 51, Enc.TIMES5),
                    "controversy", new Spec(-236 + 54, Enc.U8)
            )
    );

    private static final LayoutVariant SMAL = new LayoutVariant(
            "smal",
            Map.of(
                    "potential ability", new Spec(5165, Enc.U16LE),
                    "striker", new Spec(5199, Enc.U8),
                    "finishing", new Spec(5204, Enc.TIMES5),
                    "pace", new Spec(5240, Enc.TIMES5),
                    "concentration", new Spec(5255, Enc.TIMES5),
                    "controversy", new Spec(5987, Enc.U8)
            )
    );

    private GenericSubsetVariantProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] payload = loadPayload(Path.of("games/Feyenoord_after.fm"));
        Map<String, Integer> players = new LinkedHashMap<>();
        players.put("Trauner", 16_023_929);
        players.put("Smal", 37_060_899);
        players.put("Aidoo", 13_158_416);
        players.put("Kooistra", 2_000_304_951);

        StringBuilder json = new StringBuilder(16000);
        json.append("{\n  \"players\": {\n");
        int idx = 0;
        for (Map.Entry<String, Integer> entry : players.entrySet()) {
            Integer personPair = findPersonPair(payload, entry.getValue());
            json.append("    ").append(q(entry.getKey())).append(": {\n");
            fld(json, "playerId", Integer.toUnsignedString(entry.getValue()), 6, true);
            fld(json, "personPair", personPair == null ? "null" : Integer.toString(personPair), 6, true);
            if (personPair != null) {
                renderVariant(json, payload, personPair, TRAUNER, true);
                renderVariant(json, payload, personPair, SMAL, false);
            }
            json.append("    }");
            if (++idx < players.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n}\n");
        System.out.print(json);
    }

    private static void renderVariant(StringBuilder json, byte[] payload, int personPair, LayoutVariant variant, boolean comma) {
        int score = 0;
        json.append("      ").append(q(variant.name())).append(": {\n");
        json.append("        \"fields\": {\n");
        int i = 0;
        for (Map.Entry<String, Spec> field : variant.fields().entrySet()) {
            Decoded decoded = field.getValue().enc().decode(payload, personPair + field.getValue().delta());
            if (plausible(field.getKey(), decoded.value())) {
                score++;
            }
            json.append("          ").append(q(field.getKey())).append(": ")
                    .append(decoded.value() == null ? "null" : decoded.value());
            if (++i < variant.fields().size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("        },\n");
        json.append("        \"score\": ").append(score).append('\n');
        json.append("      }");
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static boolean plausible(String field, Integer value) {
        if (value == null) return false;
        return switch (field) {
            case "potential ability" -> value >= 1 && value <= 250;
            case "striker", "controversy" -> value >= 0 && value <= 20;
            default -> value >= 1 && value <= 20;
        };
    }

    private static Integer findPersonPair(byte[] payload, int playerId) {
        byte b0 = (byte) (playerId & 0xFF);
        byte b1 = (byte) ((playerId >>> 8) & 0xFF);
        byte b2 = (byte) ((playerId >>> 16) & 0xFF);
        byte b3 = (byte) ((playerId >>> 24) & 0xFF);
        for (int offset = 0; offset + 8 <= payload.length && offset < PERSON_BLOCK_MAX_OFFSET; offset++) {
            if (payload[offset] == b0 && payload[offset + 1] == b1 && payload[offset + 2] == b2 && payload[offset + 3] == b3
                    && payload[offset + 4] == b0 && payload[offset + 5] == b1 && payload[offset + 6] == b2 && payload[offset + 7] == b3) {
                return offset;
            }
        }
        return null;
    }

    private static byte[] loadPayload(Path path) throws IOException {
        try (InputStream raw = new BufferedInputStream(Files.newInputStream(path));
             InputStream skipped = skipFully(raw, FMF_ZSTD_OFFSET);
             ZstdInputStream zstd = new ZstdInputStream(skipped)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            while (true) {
                try {
                    int read = zstd.read(buffer);
                    if (read < 0) break;
                    output.write(buffer, 0, read);
                } catch (ZstdIOException ex) {
                    if (output.size() > 0 && ex.getMessage() != null && ex.getMessage().contains("Unknown frame descriptor")) break;
                    throw ex;
                }
            }
            return output.toByteArray();
        }
    }

    private static InputStream skipFully(InputStream input, long bytes) throws IOException {
        long remaining = bytes;
        while (remaining > 0) {
            long skipped = input.skip(remaining);
            if (skipped <= 0) {
                if (input.read() == -1) throw new IOException("Unexpected EOF while skipping FMF wrapper");
                skipped = 1;
            }
            remaining -= skipped;
        }
        return input;
    }

    private static void fld(StringBuilder json, String name, String value, int indent, boolean comma) {
        json.append(" ".repeat(indent)).append(q(name)).append(": ").append(value);
        if (comma) json.append(',');
        json.append('\n');
    }

    private static String q(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record LayoutVariant(String name, Map<String, Spec> fields) {}
    private record Spec(int delta, Enc enc) {}
    private record Decoded(Integer value) {}

    private enum Enc {
        U8 { Decoded decode(byte[] p, int o) { return new Decoded(p[o] & 0xFF); } },
        TIMES5 { Decoded decode(byte[] p, int o) { int s = p[o] & 0xFF; return new Decoded(s % 5 == 0 ? s / 5 : null); } },
        U16LE { Decoded decode(byte[] p, int o) { return new Decoded((p[o] & 0xFF) | ((p[o+1] & 0xFF) << 8)); } };
        abstract Decoded decode(byte[] p, int o);
    }
}
