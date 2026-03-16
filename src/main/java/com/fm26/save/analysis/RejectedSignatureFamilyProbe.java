package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class RejectedSignatureFamilyProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int DUP_PAIR_DISTANCE = 4;
    private static final int PERSON_BLOCK_MIN_OFFSET = 65_000_000;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int PLAYER_EXTRA_MIN_OFFSET = 100_000_000;
    private static final int MAX_EXTRAS_PER_ID = 8;
    private static final String DEFAULT_SIGNATURE = "ytrp|ytgh|tanN|....|gh..";

    private RejectedSignatureFamilyProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length >= 1 ? Path.of(args[0]) : Path.of("games/Feyenoord_after.fm");
        String targetSignature = args.length >= 2 ? args[1] : DEFAULT_SIGNATURE;
        byte[] payload = loadPayload(save);

        List<Row> rows = findRows(payload, targetSignature);
        String json = renderJson(save, payload.length, targetSignature, rows);
        if (args.length >= 3) {
            Path output = Path.of(args[2]);
            Files.writeString(output, json, StandardCharsets.UTF_8);
            System.out.println("{\"save\": " + quote(save.toString())
                    + ", \"signature\": " + quote(targetSignature)
                    + ", \"count\": " + rows.size()
                    + ", \"output\": " + quote(output.toString()) + "}");
        } else {
            System.out.print(json);
        }
    }

    private static List<Row> findRows(byte[] payload, String targetSignature) {
        Map<Integer, PairBuckets> byId = new LinkedHashMap<>();
        for (int offset = 0; offset + 8 <= payload.length; offset++) {
            int left = u32le(payload, offset);
            if (left == 0 || left == -1) {
                continue;
            }
            if (u32le(payload, offset + DUP_PAIR_DISTANCE) != left) {
                continue;
            }
            PairBuckets buckets = byId.computeIfAbsent(left, ignored -> new PairBuckets());
            if (offset >= PERSON_BLOCK_MIN_OFFSET && offset < PERSON_BLOCK_MAX_OFFSET) {
                if (buckets.personPair == null) {
                    buckets.personPair = offset;
                }
            } else if (offset >= PLAYER_EXTRA_MIN_OFFSET && buckets.extraPairs.size() < MAX_EXTRAS_PER_ID) {
                buckets.extraPairs.add(offset);
            }
        }

        List<Row> rows = new ArrayList<>();
        for (Map.Entry<Integer, PairBuckets> entry : byId.entrySet()) {
            PairBuckets buckets = entry.getValue();
            if (buckets.personPair == null || buckets.extraPairs.isEmpty()) {
                continue;
            }
            if (buckets.extraPairs.stream().anyMatch(extra -> hasAcceptedShape(payload, extra))) {
                continue;
            }
            int extraPair = buckets.extraPairs.get(0);
            String signature = signatureAt(payload, extraPair);
            if (!signature.equals(targetSignature)) {
                continue;
            }
            rows.add(new Row(entry.getKey(), buckets.personPair, extraPair, signature,
                    ascii(payload, extraPair + 8, 12),
                    ascii(payload, extraPair + 34, 12),
                    ascii(payload, extraPair + 51, 12),
                    ascii(payload, extraPair + 65, 12),
                    ascii(payload, extraPair + 73, 12)));
        }
        rows.sort(Comparator.comparingInt(Row::personPair));
        return rows;
    }

    private static String signatureAt(byte[] payload, int extraPair) {
        return ascii(payload, extraPair + 8, 4) + "|"
                + ascii(payload, extraPair + 34, 4) + "|"
                + ascii(payload, extraPair + 51, 4) + "|"
                + ascii(payload, extraPair + 65, 4) + "|"
                + ascii(payload, extraPair + 73, 4);
    }

    private static boolean hasAcceptedShape(byte[] payload, int extraPair) {
        if (extraPair < 32 || extraPair + 80 >= payload.length) {
            return false;
        }
        return payload[extraPair + 8] == 'y'
                && payload[extraPair + 9] == 't'
                && payload[extraPair + 10] == 'r'
                && payload[extraPair + 11] == 'p'
                && payload[extraPair + 34] == 'y'
                && payload[extraPair + 35] == 't'
                && payload[extraPair + 36] == 'g'
                && payload[extraPair + 37] == 'h'
                && payload[extraPair + 51] == 't'
                && payload[extraPair + 52] == 'a'
                && payload[extraPair + 53] == 'n'
                && payload[extraPair + 54] == 'N'
                && payload[extraPair + 65] == 's'
                && payload[extraPair + 66] == 'r'
                && payload[extraPair + 67] == 'e'
                && payload[extraPair + 68] == 'v'
                && payload[extraPair + 73] == 'C'
                && payload[extraPair + 74] == 'A'
                && payload[extraPair + 75] == 'p'
                && payload[extraPair + 76] == 'U';
    }

    private static String ascii(byte[] payload, int offset, int length) {
        if (offset < 0 || offset + length > payload.length) {
            return "";
        }
        StringBuilder out = new StringBuilder(length);
        for (int i = offset; i < offset + length; i++) {
            int value = payload[i] & 0xFF;
            out.append(value >= 32 && value <= 126 ? (char) value : '.');
        }
        return out.toString();
    }

    private static String renderJson(Path save, int payloadSize, String targetSignature, List<Row> rows) {
        StringBuilder json = new StringBuilder(256_000);
        json.append("{\n");
        field(json, 2, "save", quote(save.toString()), true);
        field(json, 2, "payloadSize", Integer.toString(payloadSize), true);
        field(json, 2, "signature", quote(targetSignature), true);
        field(json, 2, "count", Integer.toString(rows.size()), true);
        json.append("  \"rows\": [\n");
        for (int i = 0; i < Math.min(rows.size(), 500); i++) {
            Row row = rows.get(i);
            json.append("    {\n");
            field(json, 6, "playerId", Integer.toUnsignedString(row.id()), true);
            field(json, 6, "personPair", Integer.toString(row.personPair()), true);
            field(json, 6, "extraPair", Integer.toString(row.extraPair()), true);
            field(json, 6, "signature", quote(row.signature()), true);
            field(json, 6, "tag1", quote(row.tag1()), true);
            field(json, 6, "tag2", quote(row.tag2()), true);
            field(json, 6, "tag3", quote(row.tag3()), true);
            field(json, 6, "tag4", quote(row.tag4()), true);
            field(json, 6, "tag5", quote(row.tag5()), false);
            json.append("    }");
            if (i + 1 < Math.min(rows.size(), 500)) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n}\n");
        return json.toString();
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

    private static int u32le(byte[] payload, int offset) {
        return (payload[offset] & 0xFF)
                | ((payload[offset + 1] & 0xFF) << 8)
                | ((payload[offset + 2] & 0xFF) << 16)
                | ((payload[offset + 3] & 0xFF) << 24);
    }

    private static void field(StringBuilder json, int indent, String name, String value, boolean comma) {
        json.append(" ".repeat(indent)).append(quote(name)).append(": ").append(value);
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private record Row(int id, int personPair, int extraPair, String signature,
                       String tag1, String tag2, String tag3, String tag4, String tag5) {
    }

    private static final class PairBuckets {
        private Integer personPair;
        private final List<Integer> extraPairs = new ArrayList<>();
    }
}
