package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class PlayerDiscriminatorProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int DUP_PAIR_DISTANCE = 4;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;

    private PlayerDiscriminatorProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);
        byte[] payload = loadPayload(save);

        Map<String, Integer> entities = new LinkedHashMap<>();
        entities.put("trauner", 16_023_929);
        entities.put("smal", 37_060_899);
        entities.put("kooistra", 2_000_304_951);
        entities.put("aidoo", 13_158_416);
        entities.put("pinas", 2_008_328);
        entities.put("zhu", 137_228);
        entities.put("roubos", 2_002_067_575);
        entities.put("adams", 2_002_067_476);

        StringBuilder json = new StringBuilder(16384);
        json.append("{\n");
        field(json, "save", quote(save.toString()), true, true);
        field(json, "payloadSize", Integer.toString(payload.length), true, true);
        json.append("  \"entities\": {\n");
        int idx = 0;
        for (Map.Entry<String, Integer> entry : entities.entrySet()) {
            List<Integer> hits = findU32Le(payload, entry.getValue());
            List<Integer> duplicatePairs = duplicatePairs(hits);
            Integer personPair = duplicatePairs.stream().filter(o -> o < PERSON_BLOCK_MAX_OFFSET).findFirst().orElse(null);
            List<Integer> extraPairs = duplicatePairs.stream().filter(o -> personPair == null || !o.equals(personPair)).toList();
            boolean isLikelyPlayer = !extraPairs.isEmpty();

            json.append("    ").append(quote(entry.getKey())).append(": {\n");
            field(json, "id", Integer.toUnsignedString(entry.getValue()), false, true, 6);
            field(json, "hits", intList(hits), false, true, 6);
            field(json, "duplicatePairs", intList(duplicatePairs), false, true, 6);
            field(json, "personPair", personPair == null ? "null" : Integer.toString(personPair), false, true, 6);
            field(json, "extraPairs", intList(extraPairs), false, true, 6);
            field(json, "likelyPlayer", Boolean.toString(isLikelyPlayer), false, false, 6);
            json.append("    }");
            idx++;
            if (idx < entities.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n");
        json.append("}\n");
        System.out.print(json);
    }

    private static List<Integer> duplicatePairs(List<Integer> hits) {
        List<Integer> pairs = new ArrayList<>();
        for (int i = 0; i + 1 < hits.size(); i++) {
            int left = hits.get(i);
            int right = hits.get(i + 1);
            if (right - left == DUP_PAIR_DISTANCE) {
                pairs.add(left);
                i++;
            }
        }
        return pairs;
    }

    private static List<Integer> findU32Le(byte[] payload, int value) {
        List<Integer> offsets = new ArrayList<>();
        byte b0 = (byte) (value & 0xFF);
        byte b1 = (byte) ((value >>> 8) & 0xFF);
        byte b2 = (byte) ((value >>> 16) & 0xFF);
        byte b3 = (byte) ((value >>> 24) & 0xFF);
        for (int offset = 0; offset + 4 <= payload.length; offset++) {
            if (payload[offset] == b0
                    && payload[offset + 1] == b1
                    && payload[offset + 2] == b2
                    && payload[offset + 3] == b3) {
                offsets.add(offset);
            }
        }
        return offsets;
    }

    private static byte[] loadPayload(Path path) throws IOException {
        if (!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".fm")) {
            return Files.readAllBytes(path);
        }
        try (InputStream raw = new BufferedInputStream(Files.newInputStream(path));
             InputStream skipped = skipFully(raw, FMF_ZSTD_OFFSET);
             ZstdInputStream zstd = new ZstdInputStream(skipped)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            while (true) {
                try {
                    int read = zstd.read(buffer);
                    if (read < 0) {
                        break;
                    }
                    output.write(buffer, 0, read);
                } catch (ZstdIOException exception) {
                    if (output.size() > 0 && exception.getMessage() != null
                            && exception.getMessage().contains("Unknown frame descriptor")) {
                        break;
                    }
                    throw exception;
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
                if (input.read() == -1) {
                    throw new IOException("Unexpected EOF while skipping FMF wrapper");
                }
                skipped = 1;
            }
            remaining -= skipped;
        }
        return input;
    }

    private static String intList(List<Integer> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(values.get(i));
        }
        return out.append(']').toString();
    }

    private static void field(StringBuilder json, String name, String value, boolean topLevel, boolean trailingComma) {
        field(json, name, value, topLevel, trailingComma, topLevel ? 2 : 6);
    }

    private static void field(StringBuilder json, String name, String value, boolean topLevel, boolean trailingComma, int indent) {
        json.append(" ".repeat(indent)).append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
