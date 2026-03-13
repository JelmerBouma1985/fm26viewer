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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class HiddenAttributeClusterAnalyzer {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_SIZE = 1024;
    private static final int WINDOW_STEP = 16;
    private static final int SEARCH_AHEAD = 8_192;
    private static final int BYTE_GAP = 8;
    private static final int MAX_REGION_LENGTH = 96;
    private static final int MAX_REGIONS_PER_SAVE = 256;
    private static final int BUCKET_SIZE = 64;
    private static final int MAX_BUCKETS = 24;

    private HiddenAttributeClusterAnalyzer() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] base = loadPayload(inputs.baseSave());
        Map<String, PlayerChange> requested = loadChanges(inputs.hiddenCsv());

        List<SaveSummary> saves = new ArrayList<>();
        for (Map.Entry<String, PlayerChange> entry : requested.entrySet()) {
            Path save = inputs.saveDir().resolve("Trauner_" + entry.getKey() + "_only.fm");
            if (!Files.exists(save)) {
                continue;
            }
            byte[] target = loadPayload(save);
            Alignment alignment = detectAlignment(base, target);
            List<DiffRegion> regions = interestingRegions(base, target, alignment);
            saves.add(new SaveSummary(entry.getKey(), entry.getValue(), save, alignment, regions));
        }

        List<BucketSummary> buckets = bucketize(saves);
        System.out.println(renderJson(inputs, base.length, saves, buckets));
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

    private static Map<String, PlayerChange> loadChanges(Path csv) throws IOException {
        Map<String, PlayerChange> changes = new LinkedHashMap<>();
        for (String rawLine : Files.readAllLines(csv, StandardCharsets.UTF_8)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("name")) {
                continue;
            }
            String[] parts = line.split(",", 3);
            if (parts.length != 3) {
                throw new IOException("Invalid CSV row: " + line);
            }
            changes.put(parts[0], new PlayerChange(parts[0], Integer.parseInt(parts[1]), Integer.parseInt(parts[2])));
        }
        return changes;
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
                appendRegion(regions, before, after, alignment.shift(), start, offset);
                start = -1;
            }
        }
        if (start >= 0) {
            appendRegion(regions, before, after, alignment.shift(), start, limit);
        }

        return regions.stream()
                .sorted(Comparator
                        .comparingInt(DiffRegion::length)
                        .thenComparingInt(DiffRegion::start))
                .limit(MAX_REGIONS_PER_SAVE)
                .toList();
    }

    private static void appendRegion(List<DiffRegion> regions, byte[] before, byte[] after, int shift, int start, int end) {
        DiffRegion candidate = new DiffRegion(start, end, before[start] & 0xFF, after[start + shift] & 0xFF);
        if (candidate.length() > MAX_REGION_LENGTH) {
            return;
        }
        if (regions.isEmpty()) {
            regions.add(candidate);
            return;
        }
        DiffRegion previous = regions.getLast();
        if (candidate.start() - previous.end() <= BYTE_GAP) {
            DiffRegion merged = new DiffRegion(previous.start(), candidate.end(), previous.beforeValue(), previous.afterValue());
            if (merged.length() <= MAX_REGION_LENGTH) {
                regions.set(regions.size() - 1, merged);
                return;
            }
        }
        regions.add(candidate);
    }

    private static List<BucketSummary> bucketize(List<SaveSummary> saves) {
        Map<Integer, BucketBuilder> byBucket = new LinkedHashMap<>();
        for (SaveSummary save : saves) {
            for (DiffRegion region : save.regions()) {
                int bucketKey = bucketKey(region);
                BucketBuilder builder = byBucket.computeIfAbsent(bucketKey, ignored -> new BucketBuilder(bucketKey));
                builder.add(save.attributeName(), save.change(), region);
            }
        }

        return byBucket.values().stream()
                .map(BucketBuilder::build)
                .filter(bucket -> bucket.narrowSpan() > 1)
                .sorted(Comparator
                        .comparingInt(BucketSummary::saveCount).reversed()
                        .thenComparingInt(BucketSummary::narrowSpan).reversed()
                        .thenComparingInt(BucketSummary::bucketStart))
                .limit(MAX_BUCKETS)
                .toList();
    }

    private static int bucketKey(DiffRegion region) {
        int midpoint = region.start() + region.length() / 2;
        return midpoint / BUCKET_SIZE;
    }

    private static String renderJson(Inputs inputs, int basePayloadSize, List<SaveSummary> saves, List<BucketSummary> buckets) {
        StringBuilder json = new StringBuilder(24_000);
        json.append("{\n");
        field(json, "baseSave", quote(inputs.baseSave().toString()), true, true);
        field(json, "saveDir", quote(inputs.saveDir().toString()), true, true);
        field(json, "hiddenCsv", quote(inputs.hiddenCsv().toString()), true, true);
        field(json, "basePayloadSize", Integer.toString(basePayloadSize), true, true);
        field(json, "saveCount", Integer.toString(saves.size()), true, true);

        json.append("  \"saves\": [\n");
        for (int i = 0; i < saves.size(); i++) {
            SaveSummary save = saves.get(i);
            json.append("    {\n");
            field(json, "attribute", quote(save.attributeName()), false, true);
            field(json, "save", quote(save.save().toString()), false, true);
            field(json, "from", Integer.toString(save.change().from()), false, true);
            field(json, "to", Integer.toString(save.change().to()), false, true);
            field(json, "shift", Integer.toString(save.alignment().shift()), false, true);
            field(json, "regionCount", Integer.toString(save.regions().size()), false, false);
            json.append("    }");
            if (i + 1 < saves.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ],\n");

        json.append("  \"topBuckets\": [\n");
        for (int i = 0; i < buckets.size(); i++) {
            BucketSummary bucket = buckets.get(i);
            json.append("    {\n");
            field(json, "bucketStart", Integer.toString(bucket.bucketStart()), false, true);
            field(json, "bucketEnd", Integer.toString(bucket.bucketEnd()), false, true);
            field(json, "saveCount", Integer.toString(bucket.saveCount()), false, true);
            field(json, "narrowSpan", Integer.toString(bucket.narrowSpan()), false, true);
            listField(json, "attributes", bucket.attributes(), true);
            json.append("      \"regionsBySave\": {\n");
            int index = 0;
            for (Map.Entry<String, List<String>> entry : bucket.regionsBySave().entrySet()) {
                json.append("        ").append(quote(entry.getKey())).append(": [");
                List<String> values = entry.getValue();
                for (int j = 0; j < values.size(); j++) {
                    if (j > 0) {
                        json.append(", ");
                    }
                    json.append(quote(values.get(j)));
                }
                json.append("]");
                if (++index < bucket.regionsBySave().size()) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      }\n");
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

    private static void field(StringBuilder json, String name, String value, boolean topLevel, boolean trailingComma) {
        json.append(topLevel ? "  " : "      ")
                .append(quote(name))
                .append(": ")
                .append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void listField(StringBuilder json, String name, List<String> values, boolean trailingComma) {
        json.append("      ").append(quote(name)).append(": [");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(", ");
            }
            json.append(quote(values.get(i)));
        }
        json.append("]");
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

    private record Inputs(Path baseSave, Path saveDir, Path hiddenCsv) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 3) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]));
            }
            if (args.length == 0) {
                return new Inputs(Path.of("games/Feyenoord_after.fm"), Path.of("games"), Path.of("hidden.csv"));
            }
            throw new IllegalArgumentException("Usage: HiddenAttributeClusterAnalyzer <after.fm> <save_dir> <hidden.csv>");
        }
    }

    private record PlayerChange(String name, int from, int to) {
    }

    private record Alignment(int commonPrefix, int alignedStart, int shift) {
    }

    private record DiffRegion(int start, int end, int beforeValue, int afterValue) {
        private int length() {
            return end - start;
        }
    }

    private record SaveSummary(String attributeName, PlayerChange change, Path save, Alignment alignment, List<DiffRegion> regions) {
    }

    private record BucketSummary(
            int bucketStart,
            int bucketEnd,
            List<String> attributes,
            Map<String, List<String>> regionsBySave,
            int minStart,
            int maxEnd
    ) {
        private int saveCount() {
            return attributes.size();
        }

        private int narrowSpan() {
            return maxEnd - minStart;
        }
    }

    private static final class BucketBuilder {
        private final int bucket;
        private final Set<String> attributes = new LinkedHashSet<>();
        private final Map<String, List<String>> regionsBySave = new LinkedHashMap<>();
        private int minStart = Integer.MAX_VALUE;
        private int maxEnd = Integer.MIN_VALUE;

        private BucketBuilder(int bucket) {
            this.bucket = bucket;
        }

        private void add(String attribute, PlayerChange change, DiffRegion region) {
            attributes.add(attribute);
            minStart = Math.min(minStart, region.start());
            maxEnd = Math.max(maxEnd, region.end());
            regionsBySave.computeIfAbsent(attribute, ignored -> new ArrayList<>())
                    .add(region.start() + "-" + region.end() + " len=" + region.length()
                            + " byte=" + region.beforeValue() + "->" + region.afterValue()
                            + " expected=" + change.from() + "->" + change.to());
        }

        private BucketSummary build() {
            return new BucketSummary(
                    bucket * BUCKET_SIZE,
                    (bucket + 1) * BUCKET_SIZE,
                    new ArrayList<>(attributes),
                    new LinkedHashMap<>(regionsBySave),
                    minStart,
                    maxEnd
            );
        }
    }
}
