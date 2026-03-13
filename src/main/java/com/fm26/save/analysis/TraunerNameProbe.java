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

public final class TraunerNameProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int PLAYER_ID = 16_023_929;
    private static final int FIRST_NAME_ID = 0x54E7;
    private static final int LAST_NAME_ID = 0x4648;
    private static final int WINDOW = 128;

    private TraunerNameProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);
        byte[] payload = loadPayload(save);

        List<Integer> playerIdOffsets = findU32Le(payload, PLAYER_ID);
        Map<Integer, String> strings = parseStringTable(payload);
        List<Integer> stringIdHits = new ArrayList<>();
        stringIdHits.addAll(findU32Le(payload, FIRST_NAME_ID));
        stringIdHits.addAll(findU32Le(payload, LAST_NAME_ID));
        stringIdHits.sort(Integer::compareTo);

        StringBuilder out = new StringBuilder(16384);
        out.append("{\n");
        field(out, "save", quote(save.toString()), true, true);
        field(out, "payloadSize", Integer.toString(payload.length), true, true);
        field(out, "playerId", Integer.toString(PLAYER_ID), true, true);
        field(out, "playerIdOccurrences", intList(playerIdOffsets), true, true);
        out.append("  \"knownStrings\": {\n");
        field(out, "firstNameId", Integer.toString(FIRST_NAME_ID), false, true, 4);
        field(out, "firstName", quote(strings.getOrDefault(FIRST_NAME_ID, "?")), false, true, 4);
        field(out, "lastNameId", Integer.toString(LAST_NAME_ID), false, true, 4);
        field(out, "lastName", quote(strings.getOrDefault(LAST_NAME_ID, "?")), false, false, 4);
        out.append("  },\n");
        out.append("  \"playerWindows\": [\n");
        for (int i = 0; i < playerIdOffsets.size(); i++) {
            int offset = playerIdOffsets.get(i);
            int start = Math.max(0, offset - WINDOW);
            int end = Math.min(payload.length, offset + WINDOW);
            List<CandidateStringRef> nearby = collectNearbyStringRefs(payload, strings, start, end);
            out.append("    {\n");
            field(out, "offset", Integer.toString(offset), false, true, 6);
            field(out, "hex", quote(hex(slice(payload, start, end))), false, true, 6);
            out.append("      \"nearbyStringRefs\": [\n");
            for (int j = 0; j < nearby.size(); j++) {
                CandidateStringRef ref = nearby.get(j);
                out.append("        {\n");
                field(out, "offset", Integer.toString(ref.offset()), false, true, 8);
                field(out, "stringId", Integer.toString(ref.stringId()), false, true, 8);
                field(out, "value", quote(ref.value()), false, false, 8);
                out.append("        }");
                if (j + 1 < nearby.size()) {
                    out.append(',');
                }
                out.append('\n');
            }
            out.append("      ]\n");
            out.append("    }");
            if (i + 1 < playerIdOffsets.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("  ],\n");
        out.append("  \"firstNameCandidates\": [\n");
        appendCandidates(out, listCandidates(payload, FIRST_NAME_ID), true);
        out.append("  ],\n");
        out.append("  \"lastNameCandidates\": [\n");
        appendCandidates(out, listCandidates(payload, LAST_NAME_ID), false);
        out.append("  ],\n");
        field(out, "firstLastNameIdHits", intList(stringIdHits), true, false);
        out.append("}\n");
        System.out.print(out);
    }

    private static void appendCandidates(StringBuilder out, List<CandidateStringValue> values, boolean trailingComma) {
        for (int i = 0; i < values.size(); i++) {
            CandidateStringValue value = values.get(i);
            out.append("    {\n");
            field(out, "offset", Integer.toString(value.offset()), false, true, 6);
            field(out, "value", quote(value.value()), false, false, 6);
            out.append("    }");
            if (i + 1 < values.size()) {
                out.append(',');
            }
            out.append('\n');
        }
    }

    private static List<CandidateStringRef> collectNearbyStringRefs(byte[] payload, Map<Integer, String> strings, int start, int end) {
        List<CandidateStringRef> refs = new ArrayList<>();
        for (int offset = start; offset + 4 <= end; offset++) {
            int value = u32le(payload, offset);
            String string = strings.get(value);
            if (string != null) {
                refs.add(new CandidateStringRef(offset, value, string));
            }
        }
        refs.sort(Comparator.comparingInt(CandidateStringRef::offset));
        return refs;
    }

    private static Map<Integer, String> parseStringTable(byte[] payload) {
        Map<Integer, String> strings = new LinkedHashMap<>();
        for (int offset = 0; offset + 8 < payload.length; offset++) {
            int id = u32le(payload, offset);
            int length = u32le(payload, offset + 4);
            if (id <= 0 || id > 1_000_000 || length <= 0 || length > 64) {
                continue;
            }
            int stringStart = offset + 8;
            int stringEnd = stringStart + length;
            if (stringEnd > payload.length) {
                continue;
            }
            if (!looksLikeUtf8Text(payload, stringStart, length)) {
                continue;
            }
            String value = new String(payload, stringStart, length, StandardCharsets.UTF_8);
            strings.putIfAbsent(id, value);
        }
        return strings;
    }

    private static boolean looksLikeUtf8Text(byte[] payload, int start, int length) {
        int printable = 0;
        for (int i = 0; i < length; i++) {
            int c = payload[start + i] & 0xFF;
            if (c >= 32 && c <= 126) {
                printable++;
                continue;
            }
            if (c >= 0xC2) {
                continue;
            }
            return false;
        }
        return printable > 0;
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

    private static List<CandidateStringValue> listCandidates(byte[] payload, int stringId) {
        List<CandidateStringValue> values = new ArrayList<>();
        for (int offset = 0; offset + 8 < payload.length; offset++) {
            if (u32le(payload, offset) != stringId) {
                continue;
            }
            int length = u32le(payload, offset + 4);
            if (length <= 0 || length > 64 || offset + 8 + length > payload.length) {
                continue;
            }
            if (!looksLikeUtf8Text(payload, offset + 8, length)) {
                continue;
            }
            values.add(new CandidateStringValue(offset, new String(payload, offset + 8, length, StandardCharsets.UTF_8)));
        }
        return values;
    }

    private static int u32le(byte[] payload, int offset) {
        return (payload[offset] & 0xFF)
                | ((payload[offset + 1] & 0xFF) << 8)
                | ((payload[offset + 2] & 0xFF) << 16)
                | ((payload[offset + 3] & 0xFF) << 24);
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

    private static byte[] slice(byte[] bytes, int from, int to) {
        int start = Math.max(0, from);
        int end = Math.min(bytes.length, to);
        byte[] copy = new byte[Math.max(0, end - start)];
        if (copy.length > 0) {
            System.arraycopy(bytes, start, copy, 0, copy.length);
        }
        return copy;
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                builder.append(' ');
            }
            builder.append(String.format(Locale.ROOT, "%02x", bytes[i] & 0xFF));
        }
        return builder.toString();
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

    private record CandidateStringRef(int offset, int stringId, String value) {
    }

    private record CandidateStringValue(int offset, String value) {
    }
}
