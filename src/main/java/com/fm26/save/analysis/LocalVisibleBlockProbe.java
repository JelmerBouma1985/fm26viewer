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

public final class LocalVisibleBlockProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int SEARCH_RADIUS = 20_000;
    private static final int BLOCK_LENGTH = 81;

    private LocalVisibleBlockProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);
        byte[] payload = loadPayload(save);

        Map<String, Integer> players = new LinkedHashMap<>();
        players.put("Trauner", 16_023_929);
        players.put("Smal", 37_060_899);
        players.put("Kooistra", 2_000_304_951);
        players.put("Aidoo", 13_158_416);

        StringBuilder json = new StringBuilder(32768);
        json.append("{\n");
        field(json, 2, "save", quote(save.toString()), true);
        json.append("  \"players\": {\n");
        int rendered = 0;
        for (Map.Entry<String, Integer> entry : players.entrySet()) {
            Integer personPair = findPersonPair(payload, entry.getValue());
            json.append("    ").append(quote(entry.getKey())).append(": {\n");
            field(json, 6, "playerId", Integer.toUnsignedString(entry.getValue()), true);
            field(json, 6, "personPair", personPair == null ? "null" : Integer.toString(personPair), true);
            field(json, 6, "candidates", personPair == null ? "[]" : renderCandidates(payload, personPair), false);
            json.append("    }");
            rendered++;
            if (rendered < players.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n");
        json.append("}\n");
        System.out.print(json);
    }

    private static String renderCandidates(byte[] payload, int personPair) {
        List<Candidate> candidates = new ArrayList<>();
        int start = Math.max(0, personPair - SEARCH_RADIUS);
        int end = Math.min(payload.length - BLOCK_LENGTH, personPair + SEARCH_RADIUS);
        for (int offset = start; offset <= end; offset++) {
            int score = scoreBlock(payload, offset);
            if (score < 40) {
                continue;
            }
            candidates.add(new Candidate(offset, score));
        }
        candidates.sort(Comparator.comparingInt(Candidate::score).reversed().thenComparingInt(Candidate::offset));
        if (candidates.size() > 10) {
            candidates = candidates.subList(0, 10);
        }

        StringBuilder out = new StringBuilder();
        out.append("[\n");
        for (int i = 0; i < candidates.size(); i++) {
            Candidate candidate = candidates.get(i);
            Candidate refined = refineCandidate(payload, candidate);
            out.append("        {\n");
            field(out, 10, "offset", Integer.toString(candidate.offset()), true);
            field(out, 10, "relativeToPerson", Integer.toString(candidate.offset() - personPair), true);
            field(out, 10, "score", Integer.toString(candidate.score()), true);
            field(out, 10, "refinedOffset", Integer.toString(refined.offset()), true);
            field(out, 10, "refinedRelativeToPerson", Integer.toString(refined.offset() - personPair), true);
            field(out, 10, "refinedScore", Integer.toString(refined.score()), true);
            field(out, 10, "finishing", decodeTimesFive(payload, refined.offset()), true);
            field(out, 10, "pace", decodeTimesFive(payload, refined.offset() + 36), true);
            field(out, 10, "concentration", decodeTimesFive(payload, refined.offset() + 51), true);
            field(out, 10, "height", Integer.toString(payload[refined.offset() + 80] & 0xFF), false);
            out.append("        }");
            if (i + 1 < candidates.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("      ]");
        return out.toString();
    }

    private static Candidate refineCandidate(byte[] payload, Candidate coarse) {
        Candidate best = coarse;
        for (int delta = 0; delta <= 12; delta++) {
            int offset = coarse.offset() + delta;
            if (offset + BLOCK_LENGTH > payload.length) {
                break;
            }
            int score = scoreBlock(payload, offset);
            int height = payload[offset + 80] & 0xFF;
            if (height >= 120 && height <= 220) {
                score += 8;
            }
            if (score > best.score()) {
                best = new Candidate(offset, score);
            }
        }
        return best;
    }

    private static int scoreBlock(byte[] payload, int offset) {
        int score = 0;
        for (int i = 0; i < BLOCK_LENGTH; i++) {
            int value = payload[offset + i] & 0xFF;
            if (value == 0 || value == 255) {
                continue;
            }
            if (value % 5 == 0 && value <= 100) {
                score++;
                continue;
            }
            if (i == 80 && value >= 120 && value <= 220) {
                score++;
            }
        }
        byte[] marker = new byte[]{0x01, 0x00, 0x6c, 0x07};
        for (int delta = 58; delta <= 68 && offset + delta + 4 <= payload.length; delta++) {
            if (payload[offset + delta] == marker[0]
                    && payload[offset + delta + 1] == marker[1]
                    && payload[offset + delta + 2] == marker[2]
                    && payload[offset + delta + 3] == marker[3]) {
                score += 6;
                break;
            }
        }
        return score;
    }

    private static String decodeTimesFive(byte[] payload, int offset) {
        int stored = payload[offset] & 0xFF;
        if (stored % 5 != 0) {
            return "null";
        }
        return Integer.toString(stored / 5);
    }

    private static Integer findPersonPair(byte[] payload, int playerId) {
        byte b0 = (byte) (playerId & 0xFF);
        byte b1 = (byte) ((playerId >>> 8) & 0xFF);
        byte b2 = (byte) ((playerId >>> 16) & 0xFF);
        byte b3 = (byte) ((playerId >>> 24) & 0xFF);
        for (int offset = 0; offset + 8 <= payload.length && offset < PERSON_BLOCK_MAX_OFFSET; offset++) {
            if (payload[offset] == b0
                    && payload[offset + 1] == b1
                    && payload[offset + 2] == b2
                    && payload[offset + 3] == b3
                    && payload[offset + 4] == b0
                    && payload[offset + 5] == b1
                    && payload[offset + 6] == b2
                    && payload[offset + 7] == b3) {
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

    private static void field(StringBuilder json, int indent, String name, String value, boolean comma) {
        json.append(" ".repeat(indent)).append(quote(name)).append(": ").append(value);
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record Candidate(int offset, int score) {
    }
}
