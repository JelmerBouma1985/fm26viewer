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

public final class GenericPlayerFieldProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;

    private static final List<Field> FIELDS = List.of(
            new Field("potential ability", 5165, Encoding.RAW_U16LE),
            new Field("striker", 5199, Encoding.RAW_U8),
            new Field("finishing", 5204, Encoding.TIMES_FIVE_U8),
            new Field("pace", 5240, Encoding.TIMES_FIVE_U8),
            new Field("concentration", 5255, Encoding.TIMES_FIVE_U8),
            new Field("controversy", 5987, Encoding.RAW_U8)
    );

    private GenericPlayerFieldProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);
        byte[] payload = loadPayload(save);

        Map<String, Integer> players = new LinkedHashMap<>();
        players.put("Trauner", 16_023_929);
        players.put("Smal", 37_060_899);
        players.put("Aidoo", 13_158_416);
        players.put("Kooistra", 2_000_304_951);

        StringBuilder json = new StringBuilder(16000);
        json.append("{\n");
        field(json, "save", quote(save.toString()), true, true);
        json.append("  \"players\": {\n");
        int pi = 0;
        for (Map.Entry<String, Integer> player : players.entrySet()) {
            Integer personPair = findPersonPair(payload, player.getValue());
            json.append("    ").append(quote(player.getKey())).append(": {\n");
            field(json, "playerId", Integer.toUnsignedString(player.getValue()), false, true, 6);
            field(json, "personPair", personPair == null ? "null" : Integer.toString(personPair), false, true, 6);
            json.append("      \"fields\": {\n");
            for (int i = 0; i < FIELDS.size(); i++) {
                Field f = FIELDS.get(i);
                json.append("        ").append(quote(f.name())).append(": ");
                if (personPair == null) {
                    json.append("null");
                } else {
                    int offset = personPair + f.relativeOffset();
                    Decoded d = f.encoding().decode(payload, offset);
                    json.append("{\"offset\": ").append(offset)
                            .append(", \"stored\": ").append(d.stored())
                            .append(", \"decoded\": ").append(d.decoded() == null ? "null" : d.decoded())
                            .append("}");
                }
                if (i + 1 < FIELDS.size()) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      }\n");
            json.append("    }");
            if (++pi < players.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n");
        json.append("}\n");
        System.out.print(json);
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

    private static void field(StringBuilder json, String name, String value, boolean top, boolean comma) {
        field(json, name, value, top, comma, top ? 2 : 6);
    }

    private static void field(StringBuilder json, String name, String value, boolean top, boolean comma, int indent) {
        json.append(" ".repeat(indent)).append(quote(name)).append(": ").append(value);
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record Field(String name, int relativeOffset, Encoding encoding) {
    }

    private record Decoded(int stored, Integer decoded) {
    }

    private enum Encoding {
        RAW_U8 {
            @Override
            Decoded decode(byte[] payload, int offset) {
                int stored = payload[offset] & 0xFF;
                return new Decoded(stored, stored);
            }
        },
        TIMES_FIVE_U8 {
            @Override
            Decoded decode(byte[] payload, int offset) {
                int stored = payload[offset] & 0xFF;
                Integer decoded = stored % 5 == 0 ? stored / 5 : null;
                return new Decoded(stored, decoded);
            }
        },
        RAW_U16LE {
            @Override
            Decoded decode(byte[] payload, int offset) {
                int stored = (payload[offset] & 0xFF) | ((payload[offset + 1] & 0xFF) << 8);
                return new Decoded(stored, stored);
            }
        };

        abstract Decoded decode(byte[] payload, int offset);
    }
}
