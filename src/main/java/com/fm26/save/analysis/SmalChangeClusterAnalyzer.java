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

public final class SmalChangeClusterAnalyzer {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_SIZE = 1024;
    private static final int WINDOW_STEP = 16;
    private static final int SEARCH_AHEAD = 8192;
    private static final int BYTE_GAP = 8;
    private static final int MAX_REGION_LENGTH = 128;
    private static final int MAX_REGIONS_PER_SAVE = 512;
    private static final int BUCKET_SIZE = 64;
    private static final int MIN_REGION_START = 60_000_000;

    private SmalChangeClusterAnalyzer() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.defaults();
        byte[] base = loadPayload(inputs.baseSave());
        List<SaveSummary> saves = new ArrayList<>();
        for (Path save : inputs.saves()) {
            byte[] target = loadPayload(save);
            Alignment alignment = detectAlignment(base, target);
            List<DiffRegion> regions = interestingRegions(base, target, alignment);
            saves.add(new SaveSummary(save, labelFromFileName(save.getFileName().toString()), alignment, regions));
        }
        List<BucketSummary> buckets = bucketize(saves);
        System.out.print(renderJson(inputs, saves, buckets));
    }

    private static String labelFromFileName(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("small_") || !lower.endsWith("_only.fm")) {
            return lower;
        }
        return lower.substring("small_".length(), lower.length() - "_only.fm".length());
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

    private static Alignment detectAlignment(byte[] before, byte[] after) {
        int prefix = commonPrefix(before, after);
        int searchStart = Math.min(prefix + 128, before.length - WINDOW_SIZE - 1);
        for (int probe = searchStart; probe + WINDOW_SIZE + 4096 < Math.min(before.length, 2_000_000); probe += WINDOW_STEP) {
            int hit = indexOf(after, before, probe, probe + WINDOW_SIZE, probe, SEARCH_AHEAD);
            if (hit > probe && matchesAt(before, after, probe, hit, 4096)) {
                return new Alignment(prefix, probe, hit - probe);
            }
        }
        return new Alignment(prefix, prefix, 0);
    }

    private static int commonPrefix(byte[] left, byte[] right) {
        int max = Math.min(left.length, right.length);
        int i = 0;
        while (i < max && left[i] == right[i]) {
            i++;
        }
        return i;
    }

    private static int indexOf(byte[] haystack, byte[] needleSource, int needleStart, int needleEnd, int searchStart, int searchDistance) {
        int maxStart = Math.min(haystack.length - (needleEnd - needleStart), searchStart + searchDistance);
        for (int i = Math.max(0, searchStart); i <= maxStart; i++) {
            boolean matches = true;
            for (int j = 0; j < needleEnd - needleStart; j++) {
                if (haystack[i + j] != needleSource[needleStart + j]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return i;
            }
        }
        return -1;
    }

    private static boolean matchesAt(byte[] before, byte[] after, int beforeStart, int afterStart, int length) {
        if (beforeStart + length > before.length || afterStart + length > after.length) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            if (before[beforeStart + i] != after[afterStart + i]) {
                return false;
            }
        }
        return true;
    }

    private static List<DiffRegion> interestingRegions(byte[] before, byte[] after, Alignment alignment) {
        List<DiffRegion> regions = new ArrayList<>();
        int limit = Math.min(before.length, after.length - alignment.shift());
        int start = -1;
        for (int offset = alignment.alignedStart(); offset < limit; offset++) {
            int shiftedOffset = offset + alignment.shift();
            if (before[offset] != after[shiftedOffset]) {
                if (start < 0) {
                    start = offset;
                }
            } else if (start >= 0) {
                appendRegion(regions, start, offset);
                start = -1;
            }
        }
        if (start >= 0) {
            appendRegion(regions, start, limit);
        }
        return regions.stream()
                .filter(region -> region.start() >= MIN_REGION_START)
                .sorted(Comparator.comparingInt(DiffRegion::length).thenComparingInt(DiffRegion::start))
                .limit(MAX_REGIONS_PER_SAVE)
                .toList();
    }

    private static void appendRegion(List<DiffRegion> regions, int start, int end) {
        DiffRegion candidate = new DiffRegion(start, end);
        if (candidate.length() > MAX_REGION_LENGTH) {
            return;
        }
        if (regions.isEmpty()) {
            regions.add(candidate);
            return;
        }
        DiffRegion previous = regions.getLast();
        if (candidate.start() - previous.end() <= BYTE_GAP) {
            DiffRegion merged = new DiffRegion(previous.start(), candidate.end());
            if (merged.length() <= MAX_REGION_LENGTH) {
                regions.set(regions.size() - 1, merged);
                return;
            }
        }
        regions.add(candidate);
    }

    private static List<BucketSummary> bucketize(List<SaveSummary> saves) {
        Map<Integer, BucketBuilder> buckets = new LinkedHashMap<>();
        for (SaveSummary save : saves) {
            for (DiffRegion region : save.regions()) {
                int key = ((region.start() + region.length() / 2) / BUCKET_SIZE);
                buckets.computeIfAbsent(key, ignored -> new BucketBuilder(key))
                        .add(save.label(), region);
            }
        }
        return buckets.values().stream()
                .map(BucketBuilder::build)
                .sorted(Comparator.comparingInt(BucketSummary::saveCount).reversed().thenComparingInt(BucketSummary::bucketStart))
                .limit(32)
                .toList();
    }

    private static String renderJson(Inputs inputs, List<SaveSummary> saves, List<BucketSummary> buckets) {
        StringBuilder json = new StringBuilder(32_000);
        json.append("{\n");
        field(json, "baseSave", quote(inputs.baseSave().toString()), true);
        field(json, "saveCount", Integer.toString(saves.size()), true);
        json.append("  \"saves\": [\n");
        for (int i = 0; i < saves.size(); i++) {
            SaveSummary save = saves.get(i);
            json.append("    {\n");
            nested(json, "save", quote(save.save().toString()), true);
            nested(json, "label", quote(save.label()), true);
            nested(json, "shift", Integer.toString(save.alignment().shift()), true);
            nested(json, "regionCount", Integer.toString(save.regions().size()), true);
            json.append("      \"regions\": [\n");
            for (int j = 0; j < Math.min(save.regions().size(), 24); j++) {
                DiffRegion region = save.regions().get(j);
                json.append("        {\"start\": ").append(region.start()).append(", \"end\": ").append(region.end())
                        .append(", \"length\": ").append(region.length()).append("}");
                if (j + 1 < Math.min(save.regions().size(), 24)) {
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
        json.append("  ],\n");
        json.append("  \"buckets\": [\n");
        for (int i = 0; i < buckets.size(); i++) {
            BucketSummary bucket = buckets.get(i);
            json.append("    {\n");
            nested(json, "bucketStart", Integer.toString(bucket.bucketStart()), true);
            nested(json, "bucketEnd", Integer.toString(bucket.bucketEnd()), true);
            nested(json, "saveCount", Integer.toString(bucket.saveCount()), true);
            nested(json, "labels", quote(String.join(", ", bucket.labels())), false);
            json.append("    }");
            if (i + 1 < buckets.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private static void field(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("  ").append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void nested(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("      ").append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record Inputs(Path baseSave, List<Path> saves) {
        private static Inputs defaults() {
            return new Inputs(
                    Path.of("games/Feyenoord_after.fm"),
                    List.of(
                            Path.of("games/Small_finishing_only.fm"),
                            Path.of("games/Small_pace_only.fm"),
                            Path.of("games/Small_concentration_only.fm"),
                            Path.of("games/Small_controversy_only.fm"),
                            Path.of("games/Small_potential_ability_only.fm"),
                            Path.of("games/Small_striker_only.fm"),
                            Path.of("games/Small_contract_end_only.fm"),
                            Path.of("games/Small_date_of_birth_only.fm")
                    )
            );
        }
    }

    private record Alignment(int commonPrefix, int alignedStart, int shift) {
    }

    private record DiffRegion(int start, int end) {
        private int length() {
            return end - start;
        }
    }

    private record SaveSummary(Path save, String label, Alignment alignment, List<DiffRegion> regions) {
    }

    private record BucketSummary(int bucketStart, int bucketEnd, int saveCount, List<String> labels) {
    }

    private static final class BucketBuilder {
        private final int key;
        private int minStart = Integer.MAX_VALUE;
        private int maxEnd = Integer.MIN_VALUE;
        private final List<String> labels = new ArrayList<>();

        private BucketBuilder(int key) {
            this.key = key;
        }

        private BucketBuilder add(String label, DiffRegion region) {
            minStart = Math.min(minStart, region.start());
            maxEnd = Math.max(maxEnd, region.end());
            if (!labels.contains(label)) {
                labels.add(label);
            }
            return this;
        }

        private BucketSummary build() {
            return new BucketSummary(key * BUCKET_SIZE, key * BUCKET_SIZE + BUCKET_SIZE - 1, labels.size(), List.copyOf(labels));
        }
    }
}
