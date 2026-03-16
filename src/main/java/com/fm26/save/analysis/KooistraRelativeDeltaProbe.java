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
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class KooistraRelativeDeltaProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int SEARCH_RADIUS = 20_000;
    private static final int PLAYER_ID = 2_000_304_951;

    private KooistraRelativeDeltaProbe() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, Change> changes = loadChanges(Path.of("kooistra_changes.csv"));
        Path baseSave = Path.of("games/Feyenoord_after.fm");
        byte[] basePayload = loadPayload(baseSave);
        Integer basePersonPair = findPersonPair(basePayload, PLAYER_ID);
        if (basePersonPair == null) {
            throw new IllegalStateException("Could not find Kooistra in base save");
        }

        StringBuilder json = new StringBuilder(24000);
        json.append("{\n");
        field(json, "baseSave", quote(baseSave.toString()), true, true);
        field(json, "basePersonPair", Integer.toString(basePersonPair), true, true);
        json.append("  \"results\": [\n");

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

        for (int i = 0; i < saves.size(); i++) {
            Path save = saves.get(i);
            String label = labelFromFileName(save.getFileName().toString());
            Change change = changes.get(label);
            byte[] payload = loadPayload(save);
            Integer targetPersonPair = findPersonPair(payload, PLAYER_ID);
            List<Match> matches = targetPersonPair == null ? List.of() : findMatches(basePayload, payload, basePersonPair, targetPersonPair, change);

            json.append("    {\n");
            field(json, "save", quote(save.toString()), false, true);
            field(json, "label", quote(label), false, true);
            field(json, "targetPersonPair", targetPersonPair == null ? "null" : Integer.toString(targetPersonPair), false, true);
            field(json, "matchCount", Integer.toString(matches.size()), false, true);
            json.append("      \"matches\": [\n");
            for (int j = 0; j < Math.min(matches.size(), 24); j++) {
                Match match = matches.get(j);
                json.append("        {\"relativeOffset\": ").append(match.relativeOffset())
                        .append(", \"baseAbsoluteOffset\": ").append(match.baseAbsoluteOffset())
                        .append(", \"targetAbsoluteOffset\": ").append(match.targetAbsoluteOffset())
                        .append(", \"encoding\": ").append(quote(match.encoding()))
                        .append("}");
                if (j + 1 < Math.min(matches.size(), 24)) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            if (i + 1 < saves.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n}\n");
        System.out.print(json);
    }

    private static List<Match> findMatches(byte[] base, byte[] target, int basePersonPair, int targetPersonPair, Change change) {
        List<Match> matches = new ArrayList<>();
        if (change == null) {
            return matches;
        }
        if (change.dateFrom() != null) {
            int baseDay = change.dateFrom().getDayOfYear();
            int baseYear = change.dateFrom().getYear();
            int targetDay = change.dateTo().getDayOfYear();
            int targetYear = change.dateTo().getYear();
            for (int delta = -SEARCH_RADIUS; delta <= SEARCH_RADIUS; delta++) {
                int baseOffset = basePersonPair + delta;
                int targetOffset = targetPersonPair + delta;
                if (baseOffset < 0 || targetOffset < 0 || baseOffset + 4 > base.length || targetOffset + 4 > target.length) {
                    continue;
                }
                int baseU16A = u16le(base, baseOffset);
                int baseU16B = u16le(base, baseOffset + 2);
                int targetU16A = u16le(target, targetOffset);
                int targetU16B = u16le(target, targetOffset + 2);
                if (baseU16A == baseDay && baseU16B == baseYear && targetU16A == targetDay && targetU16B == targetYear) {
                    matches.add(new Match(delta, baseOffset, targetOffset, "day_year_u16"));
                }
            }
            return matches;
        }

        int fromRaw = change.from();
        int toRaw = change.to();
        int fromTimes5 = change.from() * 5;
        int toTimes5 = change.to() * 5;
        for (int delta = -SEARCH_RADIUS; delta <= SEARCH_RADIUS; delta++) {
            int baseOffset = basePersonPair + delta;
            int targetOffset = targetPersonPair + delta;
            if (baseOffset < 0 || targetOffset < 0 || baseOffset >= base.length || targetOffset >= target.length) {
                continue;
            }
            int baseValue = base[baseOffset] & 0xFF;
            int targetValue = target[targetOffset] & 0xFF;
            if (baseValue == fromRaw && targetValue == toRaw) {
                matches.add(new Match(delta, baseOffset, targetOffset, "raw_u8"));
            }
            if (baseValue == fromTimes5 && targetValue == toTimes5) {
                matches.add(new Match(delta, baseOffset, targetOffset, "times_five_u8"));
            }
        }
        return matches;
    }

    private static String labelFromFileName(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("kooistra_") || !lower.endsWith("_only.fm")) {
            return lower;
        }
        String label = lower.substring("kooistra_".length(), lower.length() - "_only.fm".length());
        return label.equals("strenght") ? "strength" : label;
    }

    private static Map<String, Change> loadChanges(Path csv) throws IOException {
        Map<String, Change> changes = new LinkedHashMap<>();
        for (String rawLine : Files.readAllLines(csv, StandardCharsets.UTF_8)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("name")) {
                continue;
            }
            String[] parts = line.split(",", 3);
            if (parts[0].equals("dob")) {
                changes.put(parts[0], new Change(parts[0], null, null, LocalDate.parse(parts[1]), LocalDate.parse(parts[2])));
            } else {
                changes.put(parts[0], new Change(parts[0], Integer.parseInt(parts[1]), Integer.parseInt(parts[2]), null, null));
            }
        }
        return changes;
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

    private static int u16le(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) | ((bytes[offset + 1] & 0xFF) << 8);
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
        json.append(top ? "  " : "      ").append(quote(name)).append(": ").append(value);
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record Change(String name, Integer from, Integer to, LocalDate dateFrom, LocalDate dateTo) {
    }

    private record Match(int relativeOffset, int baseAbsoluteOffset, int targetAbsoluteOffset, String encoding) {
    }
}
