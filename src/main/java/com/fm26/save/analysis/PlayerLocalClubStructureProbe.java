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
import java.util.Set;

public final class PlayerLocalClubStructureProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_BEFORE = 10000;
    private static final int WINDOW_AFTER = 5000;
    private static final Set<Integer> CLUB_IDS = Set.of(1001, 1004, 1009, 1010, 1013, 1014);

    private PlayerLocalClubStructureProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));

        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("trauner_to_1009",
                new Scenario(16_023_929, 66_583_225, 66_591_480, 1013, 1009, Path.of("games/trauner_to_1009.fm")));
        scenarios.put("smal_to_1009",
                new Scenario(37_060_899, 67_755_429, 67_762_684, 1013, 1009, Path.of("games/smal_to_1009.fm")));
        scenarios.put("bos_loaned_out_to_1009",
                new Scenario(2_000_015_266, 69_655_129, 69_660_694, 1013, 1009, Path.of("games/bos_loaned_out_to_1009.fm")));
        scenarios.put("beelen_loaned_out_to_1009",
                new Scenario(37_076_406, 67_992_279, 67_999_409, 1013, 1009, Path.of("games/beelen_loaned_out_to_1009.fm")));
        scenarios.put("plug_back_to_1013",
                new Scenario(2_000_122_311, 70_076_006, 70_081_303, 1001, 1013, Path.of("games/plug_back_to_1013.fm")));
        scenarios.put("zechiel_back_to_1013",
                new Scenario(2_000_054_498, 69_857_442, 69_862_677, 1010, 1013, Path.of("games/zechiel_back_to_1013.fm")));

        StringBuilder out = new StringBuilder(65536);
        out.append("{\n");
        int index = 0;
        for (Map.Entry<String, Scenario> entry : scenarios.entrySet()) {
            Scenario scenario = entry.getValue();
            byte[] changed = loadPayload(scenario.save());
            out.append("  ").append(quote(entry.getKey())).append(": {\n");
            field(out, 4, "playerId", Integer.toUnsignedString(scenario.playerId()), true);
            field(out, 4, "basePersonPair", Integer.toString(scenario.basePersonPair()), true);
            field(out, 4, "changedPersonPair", Integer.toString(scenario.changedPersonPair()), true);
            field(out, 4, "oldClubId", Integer.toString(scenario.oldClubId()), true);
            field(out, 4, "newClubId", Integer.toString(scenario.newClubId()), true);
            field(out, 4, "baseHits", renderHits(base, scenario.basePersonPair()), true);
            field(out, 4, "changedHits", renderHits(changed, scenario.changedPersonPair()), false);
            out.append("  }");
            if (++index < scenarios.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("}\n");
        System.out.print(out);
    }

    private static String renderHits(byte[] payload, int personPair) {
        List<String> hits = new ArrayList<>();
        int start = Math.max(0, personPair - WINDOW_BEFORE);
        int end = Math.min(payload.length - 16, personPair + WINDOW_AFTER);
        for (int offset = start; offset <= end; offset++) {
            int clubId = u32le(payload, offset);
            if (!CLUB_IDS.contains(clubId)) {
                continue;
            }
            hits.add("{\"offset\":" + offset
                    + ",\"delta\":" + (offset - personPair)
                    + ",\"clubId\":" + clubId
                    + ",\"hex\":" + quote(hex(payload, offset, 24))
                    + "}");
        }
        return "[" + String.join(", ", hits) + "]";
    }

    private static String hex(byte[] payload, int offset, int length) {
        StringBuilder out = new StringBuilder(length * 3);
        int bounded = Math.min(payload.length, offset + length);
        for (int i = offset; i < bounded; i++) {
            if (i > offset) {
                out.append(' ');
            }
            out.append(String.format(Locale.ROOT, "%02x", payload[i] & 0xFF));
        }
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

    private record Scenario(int playerId, int basePersonPair, int changedPersonPair, int oldClubId, int newClubId, Path save) {
    }
}
