package com.fm26.save.analysis;

import com.fm26.save.analysis.GenericPlayerSubsetExtractor.ExtractedPlayer;
import com.fm26.save.analysis.GenericPlayerSubsetExtractor.ExtractionResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class GenericNameProbe {

    private static final int FIRST_NAME_TABLE_REFERENCE = 49_357_264;
    private static final int LAST_NAME_TABLE_REFERENCE = 53_807_583;
    private static final int STRING_SCAN_MIN_OFFSET = 48_000_000;
    private static final int STRING_SCAN_MAX_OFFSET = 66_000_000;
    private static final int NAME_SEARCH_MIN_DELTA = -2_500;
    private static final int NAME_SEARCH_MAX_DELTA = -100;
    private static final int NAME_PAIR_DISTANCE = 5;

    private GenericNameProbe() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        ExtractionResult extraction = GenericPlayerSubsetExtractor.extract(inputs.save());
        byte[] payload = Files.readAllBytes(inputs.payload());
        NameTables nameTables = buildNameTables(payload);
        Map<Integer, ExtractedPlayer> byId = new HashMap<>();
        for (ExtractedPlayer player : extraction.players()) {
            byId.put(player.id(), player);
        }

        StringBuilder out = new StringBuilder(8192);
        out.append("{\n");
        field(out, "save", quote(inputs.save().toString()), false, true, 2);
        out.append("  \"players\": [\n");
        for (int i = 0; i < inputs.playerIds().size(); i++) {
            int playerId = inputs.playerIds().get(i);
            ExtractedPlayer player = byId.get(playerId);
            out.append("    {\n");
            field(out, "playerId", Integer.toUnsignedString(playerId), false, true, 6);
            if (player == null) {
                field(out, "error", quote("not found in extractor output"), false, false, 6);
                out.append("    }");
            } else {
                field(out, "personPairOffset", Integer.toString(player.personPair()), false, true, 6);
                field(out, "family", quote(player.family()), false, true, 6);
                field(out, "confidence", quote(player.confidence()), false, true, 6);
                List<NamePairCandidate> candidates = findNamePairCandidates(payload, player.personPair(), nameTables);
                out.append("      \"candidates\": [\n");
                for (int j = 0; j < Math.min(10, candidates.size()); j++) {
                    NamePairCandidate candidate = candidates.get(j);
                    out.append("        {\n");
                    field(out, "delta", Integer.toString(candidate.delta()), false, true, 10);
                    field(out, "firstNameId", Integer.toUnsignedString(candidate.firstNameId()), false, true, 10);
                    field(out, "firstName", quote(candidate.firstName()), false, true, 10);
                    field(out, "lastNameId", Integer.toUnsignedString(candidate.lastNameId()), false, true, 10);
                    field(out, "lastName", quote(candidate.lastName()), false, true, 10);
                    field(out, "score", Integer.toString(candidate.score()), false, false, 10);
                    out.append("        }");
                    if (j + 1 < Math.min(10, candidates.size())) {
                        out.append(',');
                    }
                    out.append('\n');
                }
                out.append("      ]\n");
                out.append("    }");
            }
            if (i + 1 < inputs.playerIds().size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("  ]\n");
        out.append("}\n");
        if (inputs.output() == null) {
            System.out.print(out);
        } else {
            Files.writeString(inputs.output(), out, StandardCharsets.UTF_8);
            System.out.println("{\"output\": " + quote(inputs.output().toString()) + "}");
        }
    }

    private static NameTables buildNameTables(byte[] payload) {
        Map<Integer, ScoredString> firstNames = new HashMap<>();
        Map<Integer, ScoredString> lastNames = new HashMap<>();
        int scanEnd = Math.min(payload.length - 8, STRING_SCAN_MAX_OFFSET);
        for (int offset = Math.max(0, STRING_SCAN_MIN_OFFSET); offset < scanEnd; offset++) {
            int id = u32le(payload, offset);
            int length = u32le(payload, offset + 4);
            if (id <= 0 || length <= 0 || length > 64 || offset + 8 + length > payload.length) {
                continue;
            }
            String text = decodeCandidateString(payload, offset + 8, length);
            if (text == null) {
                continue;
            }
            int nextOffset = offset + 8 + length;
            if (nextOffset + 8 > payload.length) {
                continue;
            }
            int nextId = u32le(payload, nextOffset);
            int nextLength = u32le(payload, nextOffset + 4);
            if (nextId != id + 1 || nextLength <= 0 || nextLength > 64 || nextOffset + 8 + nextLength > payload.length) {
                continue;
            }
            if (decodeCandidateString(payload, nextOffset + 8, nextLength) == null) {
                continue;
            }
            int firstScore = scoreStringCandidate(text, offset, FIRST_NAME_TABLE_REFERENCE);
            int lastScore = scoreStringCandidate(text, offset, LAST_NAME_TABLE_REFERENCE);
            putBest(firstNames, id, text, firstScore);
            putBest(lastNames, id, text, lastScore);
        }
        return new NameTables(firstNames, lastNames);
    }

    private static void putBest(Map<Integer, ScoredString> map, int id, String text, int score) {
        if (score == Integer.MIN_VALUE) {
            return;
        }
        ScoredString current = map.get(id);
        if (current == null || score > current.score()) {
            map.put(id, new ScoredString(text, score));
        }
    }

    private static List<NamePairCandidate> findNamePairCandidates(byte[] payload, int personPair, NameTables tables) {
        List<NamePairCandidate> candidates = new ArrayList<>();
        for (int delta = NAME_SEARCH_MIN_DELTA; delta <= NAME_SEARCH_MAX_DELTA; delta++) {
            int firstOffset = personPair + delta;
            int lastOffset = firstOffset + NAME_PAIR_DISTANCE;
            if (firstOffset < 0 || lastOffset + 4 > payload.length) {
                continue;
            }
            int firstNameId = u32le(payload, firstOffset);
            int lastNameId = u32le(payload, lastOffset);
            ScoredString first = tables.firstNames().get(firstNameId);
            ScoredString last = tables.lastNames().get(lastNameId);
            if (first == null || last == null) {
                continue;
            }
            int score = first.score() + last.score() + scoreName(first.value(), true) + scoreName(last.value(), false);
            candidates.add(new NamePairCandidate(delta, firstNameId, first.value(), lastNameId, last.value(), score));
        }
        candidates.sort(Comparator.comparingInt(NamePairCandidate::score).reversed().thenComparingInt(NamePairCandidate::delta));
        return candidates;
    }

    private static int scoreStringCandidate(String value, int offset, int preferredOffset) {
        int plausibility = scoreName(value, true);
        int surnamePlausibility = scoreName(value, false);
        int bestPlausibility = Math.max(plausibility, surnamePlausibility);
        if (bestPlausibility < 0) {
            return Integer.MIN_VALUE;
        }
        return bestPlausibility * 1000 - Math.abs(offset - preferredOffset);
    }

    private static int scoreName(String value, boolean firstName) {
        if (value == null || value.isBlank() || value.length() > 32) {
            return Integer.MIN_VALUE;
        }
        int score = 0;
        if (Character.isUpperCase(value.charAt(0))) {
            score += 4;
        }
        boolean hasLetter = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isLetter(c)) {
                hasLetter = true;
                continue;
            }
            if (c == ' ' || c == '-' || c == '\'' || c == '’' || c == '.') {
                continue;
            }
            return Integer.MIN_VALUE;
        }
        if (!hasLetter) {
            return Integer.MIN_VALUE;
        }
        if (value.equals(value.toUpperCase(Locale.ROOT)) || value.startsWith("BASIC_")) {
            return Integer.MIN_VALUE;
        }
        if (firstName && value.indexOf(' ') >= 0) {
            score -= 2;
        }
        score += Math.max(0, 12 - value.length());
        return score;
    }

    private static String decodeCandidateString(byte[] payload, int start, int length) {
        try {
            String decoded = new String(payload, start, length, StandardCharsets.UTF_8);
            if (decoded.indexOf('\uFFFD') >= 0) {
                return null;
            }
            for (int i = 0; i < decoded.length(); i++) {
                if (Character.isLetter(decoded.charAt(i))) {
                    return decoded;
                }
            }
            return null;
        } catch (RuntimeException exception) {
            return null;
        }
    }

    private static int u32le(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF)
                | ((bytes[offset + 1] & 0xFF) << 8)
                | ((bytes[offset + 2] & 0xFF) << 16)
                | ((bytes[offset + 3] & 0xFF) << 24);
    }

    private static void field(StringBuilder out, String key, String value, boolean nested, boolean comma, int indent) {
        out.append(" ".repeat(indent)).append(quote(key)).append(": ").append(value);
        if (comma) {
            out.append(',');
        }
        out.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private record Inputs(Path save, Path payload, Path output, List<Integer> playerIds) {
        private static Inputs fromArgs(String[] args) {
            Path save = args.length >= 1 ? Path.of(args[0]) : Path.of("games/Feyenoord_after.fm");
            Path payload = args.length >= 2 ? Path.of(args[1]) : Path.of("/tmp/feyenoord_after_full.bin");
            Path output = args.length >= 3 ? Path.of(args[2]) : null;
            List<Integer> playerIds = new ArrayList<>();
            if (args.length >= 4) {
                for (int i = 3; i < args.length; i++) {
                    playerIds.add(Integer.parseUnsignedInt(args[i]));
                }
            } else {
                playerIds = List.of(16_023_929, 7_458_500, 18_108_540, 19_047_778, 352);
            }
            return new Inputs(save, payload, output, playerIds);
        }
    }

    private record NameTables(Map<Integer, ScoredString> firstNames, Map<Integer, ScoredString> lastNames) {
    }

    private record ScoredString(String value, int score) {
    }

    private record NamePairCandidate(int delta, int firstNameId, String firstName, int lastNameId, String lastName, int score) {
    }
}
