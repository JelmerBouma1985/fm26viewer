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

public final class RejectedExtraShapeProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int DUP_PAIR_DISTANCE = 4;
    private static final int PERSON_BLOCK_MIN_OFFSET = 65_000_000;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int PLAYER_EXTRA_MIN_OFFSET = 100_000_000;
    private static final int MAX_EXTRAS_PER_ID = 8;

    private RejectedExtraShapeProbe() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] payload = loadPayload(inputs.save());
        ProbeResult result = probeRejectedCandidates(payload);
        String json = renderJson(inputs.save(), payload.length, result);
        if (inputs.output() == null) {
            System.out.print(json);
        } else {
            Files.writeString(inputs.output(), json, StandardCharsets.UTF_8);
            System.out.println("{\"save\": " + quote(inputs.save().toString())
                    + ", \"output\": " + quote(inputs.output().toString())
                    + ", \"rejectedCandidates\": " + result.rejected().size()
                    + ", \"signatureFamilies\": " + result.signatureCounts().size() + "}");
        }
    }

    private static ProbeResult probeRejectedCandidates(byte[] payload) {
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
            } else if (offset >= PLAYER_EXTRA_MIN_OFFSET && buckets.extraPairs.size() < MAX_EXTRAS_PER_ID) {
                buckets.extraPairs.add(offset);
            }
        }

        List<RejectedCandidate> rejected = new ArrayList<>();
        Map<String, Integer> signatureCounts = new LinkedHashMap<>();
        for (Map.Entry<Integer, PairBuckets> entry : byId.entrySet()) {
            PairBuckets buckets = entry.getValue();
            if (buckets.personPair == null || buckets.extraPairs.isEmpty()) {
                continue;
            }
            boolean accepted = buckets.extraPairs.stream().anyMatch(extra -> hasPlayerExtraShape(payload, extra));
            if (accepted) {
                continue;
            }
            int extra = buckets.extraPairs.get(0);
            String signature = signatureAt(payload, extra);
            signatureCounts.merge(signature, 1, Integer::sum);
            rejected.add(new RejectedCandidate(entry.getKey(), buckets.personPair, extra, signature));
        }

        rejected.sort(Comparator.comparingInt(RejectedCandidate::personPair));
        return new ProbeResult(rejected, signatureCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .toList());
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
            return "out?";
        }
        byte[] slice = new byte[length];
        System.arraycopy(payload, offset, slice, 0, length);
        StringBuilder out = new StringBuilder(length);
        for (byte value : slice) {
            int unsigned = value & 0xFF;
            out.append(unsigned >= 32 && unsigned <= 126 ? (char) unsigned : '.');
        }
        return out.toString();
    }

    private static boolean hasPlayerExtraShape(byte[] payload, int extraPair) {
        if (extraPair < 32 || extraPair + 80 >= payload.length) {
            return false;
        }
        return payload[extraPair + 8] == 'y'
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
    }

    private static String renderJson(Path save, int payloadSize, ProbeResult result) {
        StringBuilder json = new StringBuilder(256_000);
        json.append("{\n");
        appendField(json, "save", quote(save.toString()), true);
        appendField(json, "payloadSize", Integer.toString(payloadSize), true);
        appendField(json, "rejectedCandidateCount", Integer.toString(result.rejected().size()), true);
        json.append("  \"signatureCounts\": [\n");
        for (int i = 0; i < result.signatureCounts().size(); i++) {
            Map.Entry<String, Integer> entry = result.signatureCounts().get(i);
            json.append("    {")
                    .append(quote("signature")).append(": ").append(quote(entry.getKey())).append(", ")
                    .append(quote("count")).append(": ").append(entry.getValue())
                    .append("}");
            if (i + 1 < result.signatureCounts().size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ],\n");
        json.append("  \"rejected\": [\n");
        for (int i = 0; i < Math.min(200, result.rejected().size()); i++) {
            RejectedCandidate candidate = result.rejected().get(i);
            json.append("    {\n");
            appendNestedField(json, "playerId", Integer.toUnsignedString(candidate.id()), true);
            appendNestedField(json, "personPairOffset", Integer.toString(candidate.personPair()), true);
            appendNestedField(json, "extraPairOffset", Integer.toString(candidate.extraPair()), true);
            appendNestedField(json, "signature", quote(candidate.signature()), false);
            json.append("    }");
            if (i + 1 < Math.min(200, result.rejected().size())) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
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

    private static int u32le(byte[] block, int offset) {
        return (block[offset] & 0xFF)
                | ((block[offset + 1] & 0xFF) << 8)
                | ((block[offset + 2] & 0xFF) << 16)
                | ((block[offset + 3] & 0xFF) << 24);
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
            return new Inputs(Path.of("games/Feyenoord_after.fm"), null);
        }
    }

    private record RejectedCandidate(int id, int personPair, int extraPair, String signature) {
    }

    private record ProbeResult(List<RejectedCandidate> rejected, List<Map.Entry<String, Integer>> signatureCounts) {
    }

    private static final class PairBuckets {
        private Integer personPair;
        private final List<Integer> extraPairs = new ArrayList<>();
    }
}
