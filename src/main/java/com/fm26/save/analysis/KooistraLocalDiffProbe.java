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
import java.util.List;
import java.util.Locale;

public final class KooistraLocalDiffProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int PLAYER_ID = 2_000_304_951;
    private static final int WINDOW_RADIUS = 1_200;

    private KooistraLocalDiffProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));
        int basePair = findPersonPair(base, PLAYER_ID);
        List<Path> saves = List.of(
                Path.of("games/Kooistra_ambition_only.fm"),
                Path.of("games/Kooistra_dribbling_only.fm"),
                Path.of("games/Kooistra_marking_only.fm"),
                Path.of("games/Kooistra_leadership_only.fm"),
                Path.of("games/Kooistra_concentration_only.fm"),
                Path.of("games/Kooistra_stamina_only.fm"),
                Path.of("games/Kooistra_strenght_only.fm"),
                Path.of("games/Kooistra_defensive_midfielder_only.fm"),
                Path.of("games/Kooistra_dob_only.fm")
        );

        StringBuilder json = new StringBuilder(32000);
        json.append("{\n");
        json.append("  \"basePersonPair\": ").append(basePair).append(",\n");
        json.append("  \"results\": [\n");
        for (int i = 0; i < saves.size(); i++) {
            Path save = saves.get(i);
            byte[] target = loadPayload(save);
            int targetPair = findPersonPair(target, PLAYER_ID);
            List<RelDiff> diffs = new ArrayList<>();
            for (int delta = -WINDOW_RADIUS; delta <= WINDOW_RADIUS; delta++) {
                int bo = basePair + delta;
                int to = targetPair + delta;
                if (bo < 0 || to < 0 || bo >= base.length || to >= target.length) continue;
                int bv = base[bo] & 0xFF;
                int tv = target[to] & 0xFF;
                if (bv != tv) diffs.add(new RelDiff(delta, bo, to, bv, tv));
            }
            json.append("    {\n");
            fld(json, "save", q(save.toString()), true);
            fld(json, "targetPersonPair", Integer.toString(targetPair), true);
            fld(json, "diffCount", Integer.toString(diffs.size()), true);
            json.append("      \"diffs\": [\n");
            for (int j = 0; j < Math.min(diffs.size(), 40); j++) {
                RelDiff d = diffs.get(j);
                json.append("        {\"delta\": ").append(d.delta())
                        .append(", \"baseOffset\": ").append(d.baseOffset())
                        .append(", \"targetOffset\": ").append(d.targetOffset())
                        .append(", \"base\": ").append(d.baseValue())
                        .append(", \"target\": ").append(d.targetValue()).append("}");
                if (j + 1 < Math.min(diffs.size(), 40)) json.append(',');
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            if (i + 1 < saves.size()) json.append(',');
            json.append('\n');
        }
        json.append("  ]\n}\n");
        System.out.print(json);
    }

    private static int findPersonPair(byte[] payload, int playerId) {
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
        throw new IllegalStateException("player pair not found");
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

    private static void fld(StringBuilder json, String name, String value, boolean comma) {
        json.append("      ").append(q(name)).append(": ").append(value);
        if (comma) json.append(',');
        json.append('\n');
    }

    private static String q(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record RelDiff(int delta, int baseOffset, int targetOffset, int baseValue, int targetValue) {}
}
