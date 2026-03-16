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
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class StandardVisibleBlockProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int DUP_PAIR_DISTANCE = 4;
    private static final int PERSON_BLOCK_MIN_OFFSET = 65_000_000;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int SEARCH_MIN_DELTA = -1_910;
    private static final int SEARCH_MAX_DELTA = -450;
    private static final int BLOCK_LENGTH = 52;
    private static final Map<String, Integer> STANDARD_FIELDS = Map.ofEntries(
            Map.entry("finishing", 0),
            Map.entry("heading", 1),
            Map.entry("long_shots", 2),
            Map.entry("marking", 3),
            Map.entry("off_the_ball", 4),
            Map.entry("passing", 5),
            Map.entry("tackling", 7),
            Map.entry("vision", 8),
            Map.entry("anticipation", 15),
            Map.entry("decisions", 16),
            Map.entry("positioning", 18),
            Map.entry("first_touch", 20),
            Map.entry("technique", 21),
            Map.entry("flair", 24),
            Map.entry("corners", 25),
            Map.entry("teamwork", 26),
            Map.entry("work_rate", 27),
            Map.entry("long_throws", 28),
            Map.entry("acceleration", 32),
            Map.entry("free_kicks", 33),
            Map.entry("strength", 34),
            Map.entry("stamina", 35),
            Map.entry("pace", 36),
            Map.entry("jumping_reach", 37),
            Map.entry("leadership", 38),
            Map.entry("balance", 40),
            Map.entry("bravery", 41),
            Map.entry("aggression", 43),
            Map.entry("agility", 44),
            Map.entry("natural_fitness", 48),
            Map.entry("determination", 49),
            Map.entry("composure", 50),
            Map.entry("concentration", 51)
    );

    private static final int[] STANDARD_POSITIONS = STANDARD_FIELDS.values().stream()
            .mapToInt(Integer::intValue)
            .sorted()
            .toArray();

    private StandardVisibleBlockProbe() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] payload = loadPayload(inputs.save());
        Map<Integer, Integer> personPairs = findPersonPairs(payload);

        StringBuilder json = new StringBuilder(64_000);
        json.append("{\n");
        appendField(json, "save", quote(inputs.save().toString()), true);
        json.append("  \"players\": [\n");
        for (int i = 0; i < inputs.playerIds().size(); i++) {
            int playerId = inputs.playerIds().get(i);
            Integer personPair = personPairs.get(playerId);
            json.append("    {\n");
            appendNestedField(json, "playerId", Integer.toString(playerId), true);
            if (personPair == null) {
                appendNestedField(json, "found", "false", false);
                json.append("    }");
            } else {
                appendNestedField(json, "found", "true", true);
                appendNestedField(json, "personPairOffset", Integer.toString(personPair), true);
                InferredCandidate inferred = inferStandardCandidate(payload, personPair);
                if (inferred != null) {
                    appendNestedField(json, "inferredStartDelta", Integer.toString(inferred.startDelta()), true);
                    appendNestedField(json, "inferredBias", Integer.toString(inferred.bias()), true);
                    appendNestedField(json, "inferredScore", Integer.toString(inferred.score()), true);
                    appendNestedField(json, "inferredDecoded", renderDecoded(payload, personPair + inferred.startDelta(), inferred.bias()), true);
                }
                List<CandidateCluster> clusters = findClusters(payload, personPair);
                json.append("      \"clusters\": [\n");
                for (int j = 0; j < clusters.size(); j++) {
                    CandidateCluster cluster = clusters.get(j);
                    json.append("        {\n");
                    appendDeepField(json, "startDelta", Integer.toString(cluster.startDelta()), true);
                    appendDeepField(json, "endDelta", Integer.toString(cluster.endDelta()), true);
                    appendDeepField(json, "candidateCount", Integer.toString(cluster.deltas().size()), true);
                    appendDeepField(json, "decoded", renderDecoded(payload, personPair + cluster.endDelta(), 0), true);
                    appendDeepField(json, "tailBytes", renderTail(payload, personPair + cluster.endDelta()), false);
                    json.append("        }");
                    if (j + 1 < clusters.size()) {
                        json.append(',');
                    }
                    json.append('\n');
                }
                json.append("      ]\n");
                json.append("    }");
            }
            if (i + 1 < inputs.playerIds().size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        System.out.print(json);
    }

    private static Map<Integer, Integer> findPersonPairs(byte[] payload) {
        Map<Integer, Integer> personPairs = new LinkedHashMap<>();
        for (int offset = PERSON_BLOCK_MIN_OFFSET; offset + 8 <= Math.min(payload.length, PERSON_BLOCK_MAX_OFFSET); offset++) {
            int id = u32le(payload, offset);
            if (id == 0 || id == -1) {
                continue;
            }
            if (u32le(payload, offset + DUP_PAIR_DISTANCE) != id) {
                continue;
            }
            personPairs.putIfAbsent(id, offset);
        }
        return personPairs;
    }

    private static List<CandidateCluster> findClusters(byte[] payload, int personPair) {
        List<Integer> deltas = new ArrayList<>();
        for (int delta = SEARCH_MIN_DELTA; delta <= SEARCH_MAX_DELTA; delta++) {
            int start = personPair + delta;
            if (start < 0 || start + BLOCK_LENGTH > payload.length) {
                continue;
            }
            boolean allTimesFive = true;
            for (int i = 0; i < BLOCK_LENGTH; i++) {
                int stored = payload[start + i] & 0xFF;
                if (stored < 5 || stored > 100 || stored % 5 != 0) {
                    allTimesFive = false;
                    break;
                }
            }
            if (allTimesFive) {
                deltas.add(delta);
            }
        }
        if (deltas.isEmpty()) {
            return List.of();
        }

        List<CandidateCluster> clusters = new ArrayList<>();
        List<Integer> current = new ArrayList<>();
        current.add(deltas.get(0));
        for (int i = 1; i < deltas.size(); i++) {
            int delta = deltas.get(i);
            if (delta == current.get(current.size() - 1) + 1) {
                current.add(delta);
                continue;
            }
            clusters.add(new CandidateCluster(current.get(0), current.get(current.size() - 1), List.copyOf(current)));
            current = new ArrayList<>();
            current.add(delta);
        }
        clusters.add(new CandidateCluster(current.get(0), current.get(current.size() - 1), List.copyOf(current)));
        clusters.sort(Comparator.comparingInt(CandidateCluster::endDelta).reversed());
        return clusters;
    }

    private static InferredCandidate inferStandardCandidate(byte[] payload, int personPair) {
        InferredCandidate best = null;
        for (int delta = SEARCH_MIN_DELTA; delta <= SEARCH_MAX_DELTA; delta++) {
            int start = personPair + delta;
            if (start < 0 || start + 64 > payload.length) {
                continue;
            }
            if (!hasStandardTailMarker(payload, start)) {
                continue;
            }
            for (int bias = 0; bias <= 4; bias++) {
                int plausibleCount = 0;
                int residueTarget = (5 - bias) % 5;
                int residueCount = 0;
                for (int position : STANDARD_POSITIONS) {
                    int stored = payload[start + position] & 0xFF;
                    int decoded = decodeStandardVisibleValue(stored, bias);
                    if (decoded >= 1 && decoded <= 20) {
                        plausibleCount++;
                    }
                    if (stored % 5 == residueTarget) {
                        residueCount++;
                    }
                }
                InferredCandidate candidate = new InferredCandidate(delta, bias, plausibleCount, residueCount);
                if (best == null
                        || candidate.score() > best.score()
                        || (candidate.score() == best.score() && candidate.residueCount() > best.residueCount())
                        || (candidate.score() == best.score() && candidate.residueCount() == best.residueCount()
                        && candidate.startDelta() > best.startDelta())) {
                    best = candidate;
                }
            }
        }
        return best;
    }

    private static boolean hasStandardTailMarker(byte[] payload, int start) {
        int b60 = payload[start + 60] & 0xFF;
        int b61 = payload[start + 61] & 0xFF;
        int b62 = payload[start + 62] & 0xFF;
        int b63 = payload[start + 63] & 0xFF;
        return (b60 == 7 && b61 == 1 && b62 == 0 && b63 == 108)
                || (b60 == 7 && b61 == 237 && b62 == 0 && b63 == 233);
    }

    private static String renderDecoded(byte[] payload, int start, int bias) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(STANDARD_FIELDS.entrySet());
        entries.sort(Comparator.comparingInt(Map.Entry::getValue));
        for (int i = 0; i < entries.size(); i++) {
            Map.Entry<String, Integer> entry = entries.get(i);
            int value = decodeStandardVisibleValue(payload[start + entry.getValue()] & 0xFF, bias);
            json.append(quote(entry.getKey())).append(": ").append(value);
            if (i + 1 < entries.size()) {
                json.append(", ");
            }
        }
        json.append("}");
        return json.toString();
    }

    private static String renderTail(byte[] payload, int start) {
        StringBuilder bytes = new StringBuilder("[");
        for (int i = 60; i < 66; i++) {
            if (i > 60) {
                bytes.append(", ");
            }
            bytes.append(payload[start + i] & 0xFF);
        }
        bytes.append("]");
        return bytes.toString();
    }

    private static int decodeStandardVisibleValue(int stored, int bias) {
        if (stored == 0) {
            return 0;
        }
        return Math.max(1, (stored + bias) / 5);
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

    private static int u32le(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF)
                | ((bytes[offset + 1] & 0xFF) << 8)
                | ((bytes[offset + 2] & 0xFF) << 16)
                | ((bytes[offset + 3] & 0xFF) << 24);
    }

    private static void appendField(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("  ").append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void appendNestedField(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("      ").append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void appendDeepField(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("          ").append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private record CandidateCluster(int startDelta, int endDelta, List<Integer> deltas) {
    }

    private record InferredCandidate(int startDelta, int bias, int score, int residueCount) {
    }

    private record Inputs(Path save, List<Integer> playerIds) {
        private static Inputs fromArgs(String[] args) {
            if (args.length >= 2) {
                List<Integer> playerIds = new ArrayList<>();
                for (int i = 1; i < args.length; i++) {
                    playerIds.add(Integer.parseInt(args[i]));
                }
                return new Inputs(Path.of(args[0]), List.copyOf(playerIds));
            }
            return new Inputs(Path.of("games/Feyenoord_after.fm"), List.of(
                    12095040,
                    19380090,
                    37058817,
                    59136080,
                    14004589,
                    85136376,
                    91003875,
                    2000414623
            ));
        }
    }
}
