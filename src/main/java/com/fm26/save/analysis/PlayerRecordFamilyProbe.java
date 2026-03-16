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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class PlayerRecordFamilyProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_BEFORE = 32;
    private static final int WINDOW_AFTER = 64;
    private static final int MAX_OFFSETS_PER_ENTITY = 16;

    private PlayerRecordFamilyProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);
        byte[] payload = loadPayload(save);

        List<Entity> entities = List.of(
                new Entity("trauner", 16_023_929, true),
                new Entity("smal", 37_060_899, true),
                new Entity("kooistra", 2_000_304_951, true),
                new Entity("aidoo", 13_158_416, true),
                new Entity("pinas", 2_008_328, false),
                new Entity("zhu", 137_228, false),
                new Entity("adams", 2_002_067_476, false),
                new Entity("roubos", 2_002_067_575, false)
        );

        Map<String, FamilyBucket> families = new LinkedHashMap<>();
        for (Entity entity : entities) {
            List<Integer> hits = findU32Le(payload, entity.id());
            int limit = Math.min(hits.size(), MAX_OFFSETS_PER_ENTITY);
            for (int i = 0; i < limit; i++) {
                int offset = hits.get(i);
                String signature = buildStructuralSignature(payload, offset, entity.id());
                FamilyBucket bucket = families.computeIfAbsent(signature, ignored -> new FamilyBucket(signature));
                bucket.offsets.add(new OffsetHit(entity, offset));
            }
        }

        List<FamilyBucket> sorted = families.values().stream()
                .sorted(Comparator
                        .comparingInt((FamilyBucket family) -> family.playerNames().size()).reversed()
                        .thenComparingInt(family -> family.nonPlayerNames().size())
                        .thenComparing(family -> family.signature))
                .toList();

        String json = renderJson(save, payload.length, sorted);
        System.out.print(json);
    }

    private static String buildStructuralSignature(byte[] payload, int offset, int id) {
        int start = Math.max(0, offset - WINDOW_BEFORE);
        int end = Math.min(payload.length, offset + WINDOW_AFTER);
        byte[] window = new byte[end - start];
        System.arraycopy(payload, start, window, 0, window.length);

        int relative = offset - start;
        for (int i = 0; i < 4 && relative + i < window.length; i++) {
            window[relative + i] = 0;
        }

        // Also mask the immediately duplicated second copy if present.
        if (relative + 8 <= window.length && u32le(window, relative + 4) == id) {
            for (int i = 4; i < 8; i++) {
                window[relative + i] = 0;
            }
        }

        StringBuilder out = new StringBuilder(window.length);
        for (byte value : window) {
            int unsigned = value & 0xFF;
            if (unsigned == 0) {
                out.append('0');
            } else if (unsigned >= 'a' && unsigned <= 'z') {
                out.append((char) unsigned);
            } else if (unsigned >= 'A' && unsigned <= 'Z') {
                out.append((char) (unsigned + 32));
            } else if (unsigned >= '0' && unsigned <= '9') {
                out.append('d');
            } else if (unsigned <= 0x12) {
                out.append('t');
            } else if (unsigned >= 32 && unsigned < 127) {
                out.append('p');
            } else {
                out.append('.');
            }
        }
        return out.toString();
    }

    private static String renderJson(Path save, int payloadSize, List<FamilyBucket> families) {
        StringBuilder json = new StringBuilder(262_144);
        json.append("{\n");
        field(json, 2, "save", quote(save.toString()), true);
        field(json, 2, "payloadSize", Integer.toString(payloadSize), true);
        field(json, 2, "familyCount", Integer.toString(families.size()), true);
        json.append("  \"families\": [\n");
        for (int i = 0; i < families.size(); i++) {
            FamilyBucket family = families.get(i);
            json.append("    {\n");
            field(json, 6, "playerEntityCount", Integer.toString(family.playerNames().size()), true);
            field(json, 6, "nonPlayerEntityCount", Integer.toString(family.nonPlayerNames().size()), true);
            field(json, 6, "players", stringArray(family.playerNames()), true);
            field(json, 6, "nonPlayers", stringArray(family.nonPlayerNames()), true);
            field(json, 6, "sampleOffsets", intArray(family.sampleOffsets()), true);
            field(json, 6, "signatureHex", quote(family.signature), false);
            json.append("    }");
            if (i + 1 < families.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
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

    private static int u32le(byte[] block, int offset) {
        if (offset < 0 || offset + 4 > block.length) {
            return 0;
        }
        return (block[offset] & 0xFF)
                | ((block[offset + 1] & 0xFF) << 8)
                | ((block[offset + 2] & 0xFF) << 16)
                | ((block[offset + 3] & 0xFF) << 24);
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

    private static String stringArray(Set<String> values) {
        StringBuilder out = new StringBuilder("[");
        int index = 0;
        for (String value : values) {
            if (index++ > 0) {
                out.append(", ");
            }
            out.append(quote(value));
        }
        return out.append(']').toString();
    }

    private static String intArray(List<Integer> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(values.get(i));
        }
        return out.append(']').toString();
    }

    private static String quote(String value) {
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private record Entity(String name, int id, boolean player) {
    }

    private record OffsetHit(Entity entity, int offset) {
    }

    private static final class FamilyBucket {
        private final String signature;
        private final List<OffsetHit> offsets = new ArrayList<>();

        private FamilyBucket(String signature) {
            this.signature = signature;
        }

        private Set<String> playerNames() {
            Set<String> names = new LinkedHashSet<>();
            for (OffsetHit hit : offsets) {
                if (hit.entity().player()) {
                    names.add(hit.entity().name());
                }
            }
            return names;
        }

        private Set<String> nonPlayerNames() {
            Set<String> names = new LinkedHashSet<>();
            for (OffsetHit hit : offsets) {
                if (!hit.entity().player()) {
                    names.add(hit.entity().name());
                }
            }
            return names;
        }

        private List<Integer> sampleOffsets() {
            List<Integer> values = new ArrayList<>();
            for (int i = 0; i < offsets.size() && i < 8; i++) {
                values.add(offsets.get(i).offset());
            }
            return values;
        }
    }
}
