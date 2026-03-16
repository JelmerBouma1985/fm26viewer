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
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class PlayerExtensionLinkProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_BEFORE = 128;
    private static final int WINDOW_AFTER = 256;
    private static final int SEARCH_RADIUS = 4096;
    private static final int ENTRY_STRIDE = 99;
    private static final int ENTRY_START_DELTA = -128;

    private PlayerExtensionLinkProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);
        byte[] payload = loadPayload(save);

        Map<String, Anchor> anchors = new LinkedHashMap<>();
        anchors.put("trauner", new Anchor(16_023_929, 66_583_225, 111_979_709));
        anchors.put("smal", new Anchor(37_060_899, 67_755_429, 117_329_984));
        anchors.put("kooistra", new Anchor(2_000_304_951, 70_731_101, 143_317_529));
        anchors.put("aidoo", new Anchor(13_158_416, 66_453_218, 110_547_486));

        StringBuilder json = new StringBuilder(65536);
        json.append("{\n");
        field(json, 2, "save", quote(save.toString()), true);
        field(json, 2, "payloadSize", Integer.toString(payload.length), true);
        json.append("  \"anchors\": {\n");
        int rendered = 0;
        for (Map.Entry<String, Anchor> entry : anchors.entrySet()) {
            String name = entry.getKey();
            Anchor anchor = entry.getValue();
            json.append("    ").append(quote(name)).append(": {\n");
            field(json, 6, "playerId", Integer.toUnsignedString(anchor.id()), true);
            field(json, 6, "personPair", Integer.toString(anchor.personPair()), true);
            field(json, 6, "extraPair", Integer.toString(anchor.extraPair()), true);
            field(json, 6, "delta", Integer.toString(anchor.extraPair() - anchor.personPair()), true);
            field(json, 6, "windowHex", quote(renderWindow(payload, anchor.extraPair() - WINDOW_BEFORE, anchor.extraPair() + WINDOW_AFTER)), true);
            field(json, 6, "currentEntryIndex", Integer.toString(currentEntryIndex(anchor)), true);
            field(json, 6, "parsedEntries", renderEntries(payload, anchor), true);
            field(json, 6, "personRefsNearExtra", intArray(findU32(payload, anchor.extraPair() - SEARCH_RADIUS, anchor.extraPair() + SEARCH_RADIUS, anchor.personPair())), true);
            field(json, 6, "idRefsNearExtra", intArray(findU32(payload, anchor.extraPair() - SEARCH_RADIUS, anchor.extraPair() + SEARCH_RADIUS, anchor.id())), true);
            field(json, 6, "smallLocalRefs", renderInterestingRefs(payload, anchor), false);
            json.append("    }");
            rendered++;
            if (rendered < anchors.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n");
        json.append("}\n");
        System.out.print(json);
    }

    private static String renderInterestingRefs(byte[] payload, Anchor anchor) {
        StringBuilder out = new StringBuilder();
        out.append("[\n");
        int rendered = 0;
        for (int offset = Math.max(0, anchor.extraPair() - 256); offset + 4 <= Math.min(payload.length, anchor.extraPair() + 256); offset += 2) {
            int value = u32le(payload, offset);
            int deltaToPerson = value - anchor.personPair();
            if (Math.abs(deltaToPerson) > 20_000) {
                continue;
            }
            if (rendered > 0) {
                out.append(",\n");
            }
            out.append("        {\"offset\": ").append(offset)
                    .append(", \"value\": ").append(Integer.toUnsignedString(value))
                    .append(", \"deltaToPerson\": ").append(deltaToPerson)
                    .append('}');
            rendered++;
        }
        if (rendered > 0) {
            out.append('\n');
        }
        out.append("      ]");
        return out.toString();
    }

    private static String renderEntries(byte[] payload, Anchor anchor) {
        StringBuilder out = new StringBuilder();
        out.append("[\n");
        int base = anchor.extraPair() + ENTRY_START_DELTA;
        for (int i = 0; i < 4; i++) {
            int entryOffset = base + (i * ENTRY_STRIDE);
            ParsedEntry entry = parseEntry(payload, entryOffset);
            out.append("        {\n");
            appendNested(out, "offset", Integer.toString(entryOffset), true);
            appendNested(out, "current", Boolean.toString(i == currentEntryIndex(anchor)), true);
            appendNested(out, "entryTag", quote(entry.entryTag()), true);
            appendNested(out, "uniqueIdTag", quote(entry.uniqueIdTag()), true);
            appendNested(out, "uniqueId", Integer.toUnsignedString(entry.uniqueId()), true);
            appendNested(out, "propertyTag", quote(entry.propertyTag()), true);
            appendNested(out, "propertyName", quote(entry.propertyName()), true);
            appendNested(out, "valueTag", quote(entry.valueTag()), true);
            appendNested(out, "valueName", quote(entry.valueName()), true);
            appendNested(out, "fieldTag", quote(entry.fieldTag()), true);
            appendNested(out, "fieldValue", Integer.toUnsignedString(entry.fieldValue()), true);
            appendNested(out, "versTag", quote(entry.versTag()), false);
            out.append("        }");
            if (i < 3) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("      ]");
        return out.toString();
    }

    private static ParsedEntry parseEntry(byte[] payload, int offset) {
        return new ParsedEntry(
                reverseAscii(payload, offset, 4),
                reverseAscii(payload, offset + 20, 4),
                u32le(payload, offset + 29),
                reverseAscii(payload, offset + 34, 4),
                reverseAscii(payload, offset + 40, 8),
                reverseAscii(payload, offset + 60, 4),
                reverseAscii(payload, offset + 67, 4),
                reverseAscii(payload, offset + 77, 4),
                u32le(payload, offset + 83),
                reverseAscii(payload, offset + 91, 4)
        );
    }

    private static int currentEntryIndex(Anchor anchor) {
        return (-ENTRY_START_DELTA - 29) / ENTRY_STRIDE;
    }

    private static String reverseAscii(byte[] payload, int offset, int length) {
        if (offset < 0 || offset + length > payload.length) {
            return "";
        }
        StringBuilder out = new StringBuilder(length);
        for (int i = offset + length - 1; i >= offset; i--) {
            int value = payload[i] & 0xFF;
            out.append(value >= 32 && value < 127 ? (char) value : '.');
        }
        return out.toString();
    }

    private static String renderWindow(byte[] payload, int start, int end) {
        int boundedStart = Math.max(0, start);
        int boundedEnd = Math.min(payload.length, end);
        StringBuilder out = new StringBuilder((boundedEnd - boundedStart) * 3);
        for (int offset = boundedStart; offset < boundedEnd; offset++) {
            if (offset > boundedStart) {
                out.append(' ');
            }
            out.append(String.format(Locale.ROOT, "%02x", payload[offset] & 0xFF));
        }
        return out.toString();
    }

    private static int[] findU32(byte[] payload, int start, int end, int value) {
        int boundedStart = Math.max(0, start);
        int boundedEnd = Math.min(payload.length - 3, end);
        int count = 0;
        for (int offset = boundedStart; offset < boundedEnd; offset++) {
            if (u32le(payload, offset) == value) {
                count++;
            }
        }
        int[] offsets = new int[Math.min(count, 16)];
        int index = 0;
        for (int offset = boundedStart; offset < boundedEnd && index < offsets.length; offset++) {
            if (u32le(payload, offset) == value) {
                offsets[index++] = offset;
            }
        }
        return offsets;
    }

    private static String intArray(int[] values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(values[i]);
        }
        return out.append(']').toString();
    }

    private static int u32le(byte[] payload, int offset) {
        if (offset < 0 || offset + 4 > payload.length) {
            return 0;
        }
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
                .replace("\r", "\\r") + "\"";
    }

    private static void appendNested(StringBuilder json, String name, String value, boolean comma) {
        json.append("          ").append(quote(name)).append(": ").append(value);
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }

    private record Anchor(int id, int personPair, int extraPair) {
    }

    private record ParsedEntry(
            String entryTag,
            String uniqueIdTag,
            int uniqueId,
            String propertyTag,
            String propertyName,
            String valueTag,
            String valueName,
            String fieldTag,
            int fieldValue,
            String versTag
    ) {
    }
}
