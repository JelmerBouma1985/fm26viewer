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

public final class PlayerClubDiffProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW = 4096;

    private PlayerClubDiffProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path baseSave = Path.of("games/Feyenoord_after.fm");
        byte[] base = loadPayload(baseSave);

        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("trauner_to_1009", new Scenario(16_023_929, 66_583_225, 1013, 1009, Path.of("games/trauner_to_1009.fm")));
        scenarios.put("smal_to_1009", new Scenario(37_060_899, 67_755_429, 1013, 1009, Path.of("games/smal_to_1009.fm")));
        scenarios.put("bos_loaned_out_to_1009", new Scenario(2_000_015_266, 69_655_129, 1013, 1009, Path.of("games/bos_loaned_out_to_1009.fm")));
        scenarios.put("beelen_loaned_out_to_1009", new Scenario(37_076_406, 67_992_279, 1013, 1009, Path.of("games/beelen_loaned_out_to_1009.fm")));
        scenarios.put("zechiel_back_to_1013", new Scenario(2_000_054_498, 69_857_442, 1010, 1013, Path.of("games/zechiel_back_to_1013.fm")));
        scenarios.put("plug_back_to_1013", new Scenario(2_000_122_311, 70_076_006, 1001, 1013, Path.of("games/plug_back_to_1013.fm")));

        StringBuilder out = new StringBuilder(32768);
        out.append("{\n");
        int rendered = 0;
        for (Map.Entry<String, Scenario> entry : scenarios.entrySet()) {
            String name = entry.getKey();
            Scenario scenario = entry.getValue();
            byte[] changed = loadPayload(scenario.save());
            List<Change> localChanges = collectChanges(base, changed, scenario.personPair() - WINDOW, scenario.personPair() + WINDOW);
            List<Integer> baseOldRefs = findRefs(base, scenario.personPair() - WINDOW, scenario.personPair() + WINDOW, scenario.oldClubId());
            List<Integer> baseNewRefs = findRefs(base, scenario.personPair() - WINDOW, scenario.personPair() + WINDOW, scenario.newClubId());
            List<Integer> changedOldRefs = findRefs(changed, scenario.personPair() - WINDOW, scenario.personPair() + WINDOW, scenario.oldClubId());
            List<Integer> changedNewRefs = findRefs(changed, scenario.personPair() - WINDOW, scenario.personPair() + WINDOW, scenario.newClubId());

            out.append("  ").append(quote(name)).append(": {\n");
            field(out, 4, "playerId", Integer.toUnsignedString(scenario.playerId()), true);
            field(out, 4, "personPair", Integer.toString(scenario.personPair()), true);
            field(out, 4, "oldClubId", Integer.toString(scenario.oldClubId()), true);
            field(out, 4, "newClubId", Integer.toString(scenario.newClubId()), true);
            field(out, 4, "baseOldRefs", intArray(baseOldRefs, scenario.personPair()), true);
            field(out, 4, "baseNewRefs", intArray(baseNewRefs, scenario.personPair()), true);
            field(out, 4, "changedOldRefs", intArray(changedOldRefs, scenario.personPair()), true);
            field(out, 4, "changedNewRefs", intArray(changedNewRefs, scenario.personPair()), true);
            field(out, 4, "changes", renderChanges(localChanges, scenario.personPair()), false);
            out.append("  }");
            rendered++;
            if (rendered < scenarios.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("}\n");
        System.out.print(out);
    }

    private static List<Change> collectChanges(byte[] base, byte[] changed, int start, int end) {
        int boundedStart = Math.max(0, start);
        int boundedEnd = Math.min(Math.min(base.length, changed.length), end);
        List<Change> changes = new ArrayList<>();
        for (int offset = boundedStart; offset < boundedEnd; offset++) {
            int before = base[offset] & 0xFF;
            int after = changed[offset] & 0xFF;
            if (before != after) {
                changes.add(new Change(offset, before, after));
            }
        }
        return changes;
    }

    private static List<Integer> findRefs(byte[] payload, int start, int end, int value) {
        List<Integer> refs = new ArrayList<>();
        int boundedStart = Math.max(0, start);
        int boundedEnd = Math.min(payload.length - 4, end);
        for (int offset = boundedStart; offset <= boundedEnd; offset++) {
            if (u32le(payload, offset) == value) {
                refs.add(offset);
            }
        }
        return refs;
    }

    private static String renderChanges(List<Change> changes, int personPair) {
        StringBuilder out = new StringBuilder("[");
        int limit = Math.min(80, changes.size());
        for (int i = 0; i < limit; i++) {
            Change change = changes.get(i);
            if (i > 0) {
                out.append(", ");
            }
            out.append("{")
                    .append("\"offset\":").append(change.offset())
                    .append(",\"delta\":").append(change.offset() - personPair)
                    .append(",\"before\":").append(change.before())
                    .append(",\"after\":").append(change.after())
                    .append("}");
        }
        out.append("]");
        return out.toString();
    }

    private static String intArray(List<Integer> offsets, int personPair) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < offsets.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            int offset = offsets.get(i);
            out.append("{\"offset\":").append(offset)
                    .append(",\"delta\":").append(offset - personPair)
                    .append("}");
        }
        out.append("]");
        return out.toString();
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

    private record Scenario(int playerId, int personPair, int oldClubId, int newClubId, Path save) {
    }

    private record Change(int offset, int before, int after) {
    }
}
