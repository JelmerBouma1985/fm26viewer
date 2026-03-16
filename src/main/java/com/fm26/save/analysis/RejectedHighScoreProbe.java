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

public final class RejectedHighScoreProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int DUP_PAIR_DISTANCE = 4;
    private static final int PERSON_BLOCK_MIN_OFFSET = 65_000_000;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int PLAYER_EXTRA_MIN_OFFSET = 100_000_000;
    private static final String PRIMARY_SIGNATURE = "ytrp|ytgh|tanN|srev|CApU";
    private static final String SECONDARY_SIGNATURE = "ytrp|ytgh|tanN|....|gh..";

    private RejectedHighScoreProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length > 0 ? Path.of(args[0]) : Path.of("games/Feyenoord_after.fm");
        byte[] payload = loadPayload(save);
        Result result = scan(payload);
        System.out.println("{");
        System.out.println("  \"save\": " + quote(save.toString()) + ",");
        System.out.println("  \"payloadSize\": " + payload.length + ",");
        System.out.println("  \"rejectedCount\": " + result.rejectedCount + ",");
        System.out.println("  \"scoreBuckets\": " + mapJson(result.scoreBuckets) + ",");
        System.out.println("  \"examples\": [");
        for (int i = 0; i < result.examples.size(); i++) {
            Example ex = result.examples.get(i);
            System.out.println("    {\"playerId\": " + Integer.toUnsignedString(ex.id)
                    + ", \"personPair\": " + ex.personPair
                    + ", \"extraPair\": " + ex.extraPair
                    + ", \"signature\": " + quote(ex.signature)
                    + ", \"bestScore\": " + ex.bestScore
                    + ", \"bestFamily\": " + quote(ex.bestFamily) + "}"
                    + (i + 1 < result.examples.size() ? "," : ""));
        }
        System.out.println("  ]");
        System.out.println("}");
    }

    private static Result scan(byte[] payload) {
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
            } else if (offset >= PLAYER_EXTRA_MIN_OFFSET && buckets.extraPair == null) {
                buckets.extraPair = offset;
            }
        }

        Map<Integer, Integer> buckets = new LinkedHashMap<>();
        List<Example> examples = new ArrayList<>();
        int rejectedCount = 0;
        for (Map.Entry<Integer, PairBuckets> entry : byId.entrySet()) {
            PairBuckets pair = entry.getValue();
            if (pair.personPair == null || pair.extraPair == null) {
                continue;
            }
            String signature = signatureAt(payload, pair.extraPair);
            if (PRIMARY_SIGNATURE.equals(signature) || SECONDARY_SIGNATURE.equals(signature)) {
                continue;
            }
            rejectedCount++;
            Best best = bestLocal(payload, pair.personPair);
            buckets.merge(best.score, 1, Integer::sum);
            if (best.score >= 4 && examples.size() < 80) {
                examples.add(new Example(entry.getKey(), pair.personPair, pair.extraPair, signature, best.score, best.family));
            }
        }
        examples.sort(Comparator.comparingInt((Example ex) -> ex.bestScore).reversed());
        return new Result(rejectedCount, buckets, examples);
    }

    private static Best bestLocal(byte[] payload, int personPair) {
        Best best = new Best("forward_local", scoreForward(payload, personPair, 0));
        best = max(best, new Best("forward_local_m5", scoreForward(payload, personPair, -5)));
        best = max(best, new Best("forward_local_m6", scoreForward(payload, personPair, -6)));
        best = max(best, new Best("kooistra_local", scoreKooistra(payload, personPair)));
        best = max(best, new Best("trauner_local", scoreTrauner(payload, personPair)));
        return best;
    }

    private static Best max(Best left, Best right) {
        return right.score > left.score ? right : left;
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

    private static int scoreTrauner(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleU16(payload, personPair - 1184, 1, 200) ? 1 : 0;
        score += plausibleU8(payload, personPair - 1150, 0, 20) ? 1 : 0;
        score += plausibleTimes5(payload, personPair - 1145) ? 1 : 0;
        score += plausibleTimes5(payload, personPair - 1109) ? 1 : 0;
        score += plausibleTimes5(payload, personPair - 1094) ? 1 : 0;
        score += plausibleU8(payload, personPair - 182, 0, 20) ? 1 : 0;
        return score;
    }

    private static boolean plausibleU8(byte[] payload, int offset, int min, int max) {
        if (offset < 0 || offset >= payload.length) {
            return false;
        }
        int value = payload[offset] & 0xFF;
        return value >= min && value <= max;
    }

    private static boolean plausibleU16(byte[] payload, int offset, int min, int max) {
        if (offset < 0 || offset + 1 >= payload.length) {
            return false;
        }
        int value = (payload[offset] & 0xFF) | ((payload[offset + 1] & 0xFF) << 8);
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

    private static int u32le(byte[] payload, int offset) {
        return (payload[offset] & 0xFF)
                | ((payload[offset + 1] & 0xFF) << 8)
                | ((payload[offset + 2] & 0xFF) << 16)
                | ((payload[offset + 3] & 0xFF) << 24);
    }

    private static String mapJson(Map<Integer, Integer> values) {
        StringBuilder out = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<Integer, Integer> entry : values.entrySet()) {
            if (!first) {
                out.append(", ");
            }
            first = false;
            out.append(quote(Integer.toString(entry.getKey()))).append(": ").append(entry.getValue());
        }
        return out.append("}").toString();
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

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record Best(String family, int score) {
    }

    private record Example(int id, int personPair, int extraPair, String signature, int bestScore, String bestFamily) {
    }

    private record Result(int rejectedCount, Map<Integer, Integer> scoreBuckets, List<Example> examples) {
    }

    private static final class PairBuckets {
        private Integer personPair;
        private Integer extraPair;
    }
}
