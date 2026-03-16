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

public final class AllPlayersExtractor {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int DUP_PAIR_DISTANCE = 4;
    private static final int PERSON_BLOCK_MIN_OFFSET = 65_000_000;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int PLAYER_EXTRA_MIN_OFFSET = 100_000_000;
    private static final String ALT_PLAYER_SIGNATURE = "ytrp|ytgh|tanN|....|gh..";

    private AllPlayersExtractor() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] payload = loadPayload(inputs.save());
        List<PlayerCandidate> candidates = findLikelyPlayers(payload);

        String json = renderJson(inputs.save(), payload.length, candidates);
        if (inputs.output() == null) {
            System.out.print(json);
        } else {
            Files.writeString(inputs.output(), json, StandardCharsets.UTF_8);
            System.out.println("{\"save\": " + quote(inputs.save().toString())
                    + ", \"output\": " + quote(inputs.output().toString())
                    + ", \"playerCount\": " + candidates.size() + "}");
        }
    }

    private static List<PlayerCandidate> findLikelyPlayers(byte[] payload) {
        Map<Integer, PairBuckets> byId = new LinkedHashMap<>();
        for (int offset = 0; offset + 8 <= payload.length; offset++) {
            int left = u32le(payload, offset);
            if (left == 0 || left == -1) {
                continue;
            }
            if (u32le(payload, offset + DUP_PAIR_DISTANCE) != left) {
                continue;
            }
            PairBuckets buckets = byId.computeIfAbsent(left, ignored -> new PairBuckets());
            if (offset >= PERSON_BLOCK_MIN_OFFSET && offset < PERSON_BLOCK_MAX_OFFSET) {
                if (buckets.personPair == null) {
                    buckets.personPair = offset;
                }
            } else if (offset >= PLAYER_EXTRA_MIN_OFFSET) {
                if (buckets.extraPair == null) {
                    buckets.extraPair = offset;
                }
            }
        }

        List<PlayerCandidate> players = new ArrayList<>();
        for (Map.Entry<Integer, PairBuckets> entry : byId.entrySet()) {
            PairBuckets buckets = entry.getValue();
            if (buckets.personPair == null) {
                continue;
            }
            boolean acceptedByExtra = buckets.extraPair != null
                    && hasPlayerExtraShape(payload, buckets.personPair, buckets.extraPair);
            boolean acceptedByPreamble = hasStrongPlayerPreamble(payload, buckets.personPair);
            if (!acceptedByExtra && !acceptedByPreamble) {
                continue;
            }
            players.add(new PlayerCandidate(entry.getKey(), buckets.personPair, buckets.extraPair == null ? -1 : buckets.extraPair));
        }
        players.sort(Comparator.comparingInt(PlayerCandidate::personPair));
        return collapseOverlappingCandidates(payload, players);
    }

    private static List<PlayerCandidate> collapseOverlappingCandidates(byte[] payload, List<PlayerCandidate> candidates) {
        if (candidates.isEmpty()) {
            return candidates;
        }
        List<PlayerCandidate> collapsed = new ArrayList<>();
        List<PlayerCandidate> cluster = new ArrayList<>();
        cluster.add(candidates.get(0));
        for (int i = 1; i < candidates.size(); i++) {
            PlayerCandidate next = candidates.get(i);
            PlayerCandidate last = cluster.get(cluster.size() - 1);
            if (next.personPair() - last.personPair() <= 3) {
                cluster.add(next);
                continue;
            }
            collapsed.add(bestClusterCandidate(payload, cluster));
            cluster = new ArrayList<>();
            cluster.add(next);
        }
        collapsed.add(bestClusterCandidate(payload, cluster));
        return collapsed;
    }

    private static PlayerCandidate bestClusterCandidate(byte[] payload, List<PlayerCandidate> cluster) {
        return cluster.stream()
                .max(Comparator
                        .comparingInt((PlayerCandidate candidate) -> candidateRank(payload, candidate))
                        .thenComparingInt(PlayerCandidate::personPair))
                .orElseThrow();
    }

    private static int candidateRank(byte[] payload, PlayerCandidate candidate) {
        int score = bestLocalPlayerScore(payload, candidate.personPair());
        if (hasStrongPlayerPreamble(payload, candidate.personPair())) {
            score += 100;
        }
        if (candidate.extraPair() >= 0) {
            score += signatureAt(payload, candidate.extraPair()).equals(ALT_PLAYER_SIGNATURE) ? 10 : 20;
        }
        return score;
    }

    private static String renderJson(Path save, int payloadSize, List<PlayerCandidate> candidates) {
        StringBuilder json = new StringBuilder(1_000_000);
        json.append("{\n");
        appendField(json, "save", quote(save.toString()), true);
        appendField(json, "payloadSize", Integer.toString(payloadSize), true);
        appendField(json, "playerCount", Integer.toString(candidates.size()), true);
        json.append("  \"players\": [\n");
        for (int i = 0; i < candidates.size(); i++) {
            PlayerCandidate candidate = candidates.get(i);
            json.append("    {\n");
            appendNestedField(json, "playerId", Integer.toUnsignedString(candidate.id()), true);
            appendNestedField(json, "personPairOffset", Integer.toString(candidate.personPair()), true);
            appendNestedField(json, "extraPairOffset", Integer.toString(candidate.extraPair()), true);
            appendNestedField(json, "discoverySource", quote(candidate.extraPair() >= 0 ? "indexed" : "boundary_only"), true);
            appendNestedField(json, "kind", quote("likely_player"), false);
            json.append("    }");
            if (i + 1 < candidates.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private static int u32le(byte[] block, int offset) {
        return (block[offset] & 0xFF)
                | ((block[offset + 1] & 0xFF) << 8)
                | ((block[offset + 2] & 0xFF) << 16)
                | ((block[offset + 3] & 0xFF) << 24);
    }

    private static boolean hasPlayerExtraShape(byte[] payload, int personPair, int extraPair) {
        if (extraPair < 32 || extraPair + 80 >= payload.length) {
            return false;
        }
        boolean primary = payload[extraPair + 8] == 'y'
                && payload[extraPair + 9] == 't'
                && payload[extraPair + 10] == 'r'
                && payload[extraPair + 11] == 'p'
                && payload[extraPair + 34] == 'y'
                && payload[extraPair + 35] == 't'
                && payload[extraPair + 36] == 'g'
                && payload[extraPair + 37] == 'h'
                && payload[extraPair + 51] == 't'
                && payload[extraPair + 52] == 'a'
                && payload[extraPair + 53] == 'n'
                && payload[extraPair + 54] == 'N'
                && payload[extraPair + 65] == 's'
                && payload[extraPair + 66] == 'r'
                && payload[extraPair + 67] == 'e'
                && payload[extraPair + 68] == 'v'
                && payload[extraPair + 73] == 'C'
                && payload[extraPair + 74] == 'A'
                && payload[extraPair + 75] == 'p'
                && payload[extraPair + 76] == 'U';
        if (primary) {
            return true;
        }
        return signatureAt(payload, extraPair).equals(ALT_PLAYER_SIGNATURE);
    }

    private static boolean hasStrongPlayerPreamble(byte[] payload, int personPair) {
        int start = personPair - 12;
        if (start < 0 || personPair + 8 > payload.length) {
            return false;
        }
        return (payload[start] == 0x00 || payload[start] == 0x01)
                && payload[start + 1] == 0x02
                && payload[start + 2] == 0x40
                && (payload[start + 3] == 0x10 || payload[start + 3] == 0x18)
                && (payload[start + 4] == 0x04 || payload[start + 4] == 0x05)
                && payload[start + 5] == 0x00
                && payload[start + 6] == 0x00
                && payload[start + 7] == 0x00;
    }

    private static int bestLocalPlayerScore(byte[] payload, int personPair) {
        return Math.max(
                Math.max(scoreForward(payload, personPair, 0), scoreForward(payload, personPair, -5)),
                Math.max(scoreForward(payload, personPair, -6), scoreKooistra(payload, personPair))
        );
    }

    private static int scoreForward(byte[] payload, int personPair, int shift) {
        int score = 0;
        score += plausibleU8(payload, personPair + 50 + shift, 0, 20) ? 1 : 0;
        score += plausibleTimes5(payload, personPair + 56 + shift) ? 1 : 0;
        score += plausibleTimes5(payload, personPair + 92 + shift) ? 1 : 0;
        score += plausibleTimes5(payload, personPair + 107 + shift) ? 1 : 0;
        return score;
    }

    private static int scoreKooistra(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleU8(payload, personPair - 713, 0, 20) ? 1 : 0;
        score += plausibleTimes5PlusOne(payload, personPair - 702) ? 1 : 0;
        score += plausibleTimes5PlusOne(payload, personPair - 698) ? 1 : 0;
        score += plausibleTimes5PlusOne(payload, personPair - 663) ? 1 : 0;
        score += plausibleTimes5PlusOne(payload, personPair - 650) ? 1 : 0;
        return score;
    }

    private static boolean plausibleU8(byte[] payload, int offset, int min, int max) {
        if (offset < 0 || offset >= payload.length) {
            return false;
        }
        int value = payload[offset] & 0xFF;
        return value >= min && value <= max;
    }

    private static boolean plausibleTimes5(byte[] payload, int offset) {
        if (offset < 0 || offset >= payload.length) {
            return false;
        }
        int stored = payload[offset] & 0xFF;
        return stored % 5 == 0 && stored >= 5 && stored <= 100;
    }

    private static boolean plausibleTimes5PlusOne(byte[] payload, int offset) {
        if (offset < 0 || offset >= payload.length) {
            return false;
        }
        int stored = payload[offset] & 0xFF;
        return stored >= 1 && stored <= 100;
    }

    private static String signatureAt(byte[] payload, int extraPair) {
        return ascii(payload, extraPair + 8, 4) + "|"
                + ascii(payload, extraPair + 34, 4) + "|"
                + ascii(payload, extraPair + 51, 4) + "|"
                + ascii(payload, extraPair + 65, 4) + "|"
                + ascii(payload, extraPair + 73, 4);
    }

    private static String ascii(byte[] payload, int offset, int length) {
        if (offset < 0 || offset + length > payload.length) {
            return "";
        }
        StringBuilder out = new StringBuilder(length);
        for (int i = offset; i < offset + length; i++) {
            int value = payload[i] & 0xFF;
            out.append(value >= 32 && value <= 126 ? (char) value : '.');
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

    private static String quote(String value) {
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private record Inputs(Path save, Path output) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 2) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]));
            }
            if (args.length == 1) {
                return new Inputs(Path.of(args[0]), null);
            }
            if (args.length == 0) {
                return new Inputs(Path.of("games/Feyenoord_after.fm"), null);
            }
            throw new IllegalArgumentException("Usage: AllPlayersExtractor <save.fm> [output.json]");
        }
    }

    private record PlayerCandidate(int id, int personPair, int extraPair) {
    }

    private static final class PairBuckets {
        private Integer personPair;
        private Integer extraPair;
    }
}
