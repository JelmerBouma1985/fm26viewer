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

public final class EntityTypeProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW = 160;

    private EntityTypeProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);
        byte[] payload = loadPayload(save);

        Map<String, Integer> entities = new LinkedHashMap<>();
        entities.put("trauner", 16_023_929);
        entities.put("smal", 37_060_899);
        entities.put("kooistra", 2_000_304_951);
        entities.put("pinas", 2_008_328);
        entities.put("zhu", 137_228);
        entities.put("adams", 2_002_067_476);

        StringBuilder json = new StringBuilder(32768);
        json.append("{\n");
        field(json, "save", quote(save.toString()), true, true);
        field(json, "payloadSize", Integer.toString(payload.length), true, true);
        json.append("  \"entities\": {\n");
        int entityIndex = 0;
        for (Map.Entry<String, Integer> entry : entities.entrySet()) {
            List<Integer> offsets = findU32Le(payload, entry.getValue());
            json.append("    ").append(quote(entry.getKey())).append(": {\n");
            field(json, "id", Integer.toUnsignedString(entry.getValue()), false, true, 6);
            field(json, "occurrenceCount", Integer.toString(offsets.size()), false, true, 6);
            field(json, "offsets", intList(offsets), false, true, 6);
            json.append("      \"windows\": [\n");
            for (int i = 0; i < Math.min(offsets.size(), 8); i++) {
                int offset = offsets.get(i);
                int start = Math.max(0, offset - WINDOW);
                int end = Math.min(payload.length, offset + WINDOW);
                json.append("        {\n");
                field(json, "offset", Integer.toString(offset), false, true, 8);
                field(json, "hex", quote(hex(slice(payload, start, end))), false, false, 8);
                json.append("        }");
                if (i + 1 < Math.min(offsets.size(), 8)) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            entityIndex++;
            if (entityIndex < entities.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n");
        json.append("}\n");
        System.out.print(json);
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
}
