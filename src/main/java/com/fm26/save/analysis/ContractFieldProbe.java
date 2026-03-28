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
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class ContractFieldProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW = 8000;

    private ContractFieldProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));

        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("trauner_salary", new Scenario(16_023_929, 66_583_225, 14_000, 750_000, Path.of("games/trauner_salary_14k_to_750k.fm")));
        scenarios.put("smal_salary", new Scenario(37_060_899, 67_755_429, 5_250, 750_000, Path.of("games/smal_salary_5.25k_to_750k.fm")));
        scenarios.put("pablo_torre_salary", new Scenario(2_000_040_347, null, 39_000, 750_000, Path.of("games/2000040347_salary_39k_to_750k.fm")));
        scenarios.put("modric_salary", new Scenario(653_054, null, 110_000, 750_000, Path.of("games/653054_salary_110k_to_750k.fm")));
        scenarios.put("player_37021992_salary", new Scenario(37_021_992, null, 1_800, 750_000, Path.of("games/37021992_salary_1.8k_to_750k.fm")));
        scenarios.put("player_2000259904_salary", new Scenario(2_000_259_904, null, 50_000, 750_000, Path.of("games/2000259904_salary_50k_to_750k.fm")));
        scenarios.put("trauner_contract_end", new Scenario(16_023_929, 66_583_225, null, null, Path.of("games/trauner_contract_end_2026_06_30_to_2035_05_01.fm")));
        scenarios.put("smal_contract_end", new Scenario(37_060_899, 67_755_429, null, null, Path.of("games/smal_contract_end_2028_06_30_to_2035_05_01.fm")));
        scenarios.put("pablo_torre_contract_end", new Scenario(2_000_040_347, null, null, null, Path.of("games/2000040347_contract_end_2029_06_30_to_2035_05_01.fm")));
        scenarios.put("modric_contract_end", new Scenario(653_054, null, null, null, Path.of("games/653054_contract_end_2026_06_30_to_2035_05_01.fm")));
        scenarios.put("player_37021992_contract_end", new Scenario(37_021_992, null, null, null, Path.of("games/37021992_contract_end_2026_06_30_to_2035_05_01.fm")));
        scenarios.put("player_2000259904_contract_end", new Scenario(2_000_259_904, null, null, null, Path.of("games/2000259904_contract_end_2031_06_30_to_2035_05_01.fm")));

        StringBuilder out = new StringBuilder(65536);
        out.append("{\n");
        int rendered = 0;
        for (Map.Entry<String, Scenario> entry : scenarios.entrySet()) {
            Scenario scenario = entry.getValue();
            byte[] changed = loadPayload(scenario.save());
            int basePair = scenario.basePersonPair() != null
                    ? scenario.basePersonPair()
                    : resolvePersonPair(base, scenario.playerId(), null);
            int changedPair = resolvePersonPair(changed, scenario.playerId(), basePair);
            out.append("  ").append(quote(entry.getKey())).append(": {\n");
            field(out, 4, "playerId", Integer.toUnsignedString(scenario.playerId()), true);
            field(out, 4, "basePersonPair", Integer.toString(basePair), true);
            field(out, 4, "changedPersonPair", Integer.toString(changedPair), true);
            if (scenario.oldNumeric() != null) {
                field(out, 4, "oldNumeric", Integer.toString(scenario.oldNumeric()), true);
                field(out, 4, "newNumeric", Integer.toString(scenario.newNumeric()), true);
                field(out, 4, "baseOldHits", renderHits(base, basePair, scenario.oldNumeric()), true);
                field(out, 4, "changedOldHits", renderHits(changed, changedPair, scenario.oldNumeric()), true);
                field(out, 4, "changedNewHits", renderHits(changed, changedPair, scenario.newNumeric()), true);
            }
            field(out, 4, "changes", renderChanges(base, basePair, changed, changedPair), false);
            out.append("  }");
            if (++rendered < scenarios.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("}\n");
        System.out.print(out);
    }

    private static int resolvePersonPair(byte[] payload, int playerId, Integer basePersonPair) {
        byte[] pattern = u32(playerId);
        List<Integer> hits = new ArrayList<>();
        int start = 0;
        while (true) {
            int hit = indexOf(payload, pattern, start);
            if (hit < 0) {
                break;
            }
            hits.add(hit);
            start = hit + 1;
        }
        List<Integer> pairedHits = hits.stream()
                .filter(hit -> hit + 4 < payload.length && u32le(payload, hit + 4) == playerId)
                .toList();
        if (basePersonPair == null) {
            return !pairedHits.isEmpty() ? pairedHits.getFirst() : hits.getFirst();
        }
        List<Integer> candidates = !pairedHits.isEmpty() ? pairedHits : hits;
        return candidates.stream()
                .min(Comparator.comparingInt(hit -> Math.abs(hit - basePersonPair)))
                .orElseThrow(() -> new IllegalStateException("No id hit for " + Integer.toUnsignedString(playerId)));
    }

    private static String renderHits(byte[] payload, int pair, int value) {
        List<String> hits = new ArrayList<>();
        for (int off = Math.max(0, pair - WINDOW); off <= Math.min(payload.length - 4, pair + WINDOW); off++) {
            if (u32le(payload, off) == value) {
                hits.add("{\"offset\":" + off
                        + ",\"delta\":" + (off - pair)
                        + ",\"hex\":" + quote(hex(payload, off, 16))
                        + "}");
            }
        }
        return "[" + String.join(", ", hits) + "]";
    }

    private static String renderChanges(byte[] base, int basePair, byte[] changed, int changedPair) {
        List<String> changes = new ArrayList<>();
        int start = -WINDOW;
        int end = WINDOW;
        for (int rel = start; rel < end; rel++) {
            int bo = basePair + rel;
            int co = changedPair + rel;
            if (bo < 0 || co < 0 || bo >= base.length || co >= changed.length) {
                continue;
            }
            int before = base[bo] & 0xFF;
            int after = changed[co] & 0xFF;
            if (before != after) {
                changes.add("{\"rel\":" + rel
                        + ",\"baseOffset\":" + bo
                        + ",\"changedOffset\":" + co
                        + ",\"before\":" + before
                        + ",\"after\":" + after
                        + "}");
            }
        }
        if (changes.size() > 200) {
            changes = changes.subList(0, 200);
        }
        return "[" + String.join(", ", changes) + "]";
    }

    private static int indexOf(byte[] payload, byte[] needle, int start) {
        outer:
        for (int off = Math.max(0, start); off + needle.length <= payload.length; off++) {
            for (int i = 0; i < needle.length; i++) {
                if (payload[off + i] != needle[i]) {
                    continue outer;
                }
            }
            return off;
        }
        return -1;
    }

    private static byte[] u32(int value) {
        return new byte[]{
                (byte) (value & 0xFF),
                (byte) ((value >>> 8) & 0xFF),
                (byte) ((value >>> 16) & 0xFF),
                (byte) ((value >>> 24) & 0xFF)
        };
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

    private static String hex(byte[] payload, int offset, int length) {
        int end = Math.min(payload.length, offset + length);
        StringBuilder out = new StringBuilder((end - offset) * 3);
        for (int i = offset; i < end; i++) {
            if (i > offset) {
                out.append(' ');
            }
            out.append(String.format(Locale.ROOT, "%02x", payload[i] & 0xFF));
        }
        return out.toString();
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

    private record Scenario(int playerId, Integer basePersonPair, Integer oldNumeric, Integer newNumeric, Path save) {
    }
}
