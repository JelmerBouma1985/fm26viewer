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

public final class HiddenAttributeVariantAnalyzer {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_SIZE = 1024;
    private static final int WINDOW_STEP = 16;
    private static final int SEARCH_AHEAD = 8_192;
    private static final int BYTE_GAP = 8;
    private static final int MAX_REGION_LENGTH = 256;
    private static final int MAX_REGIONS_PER_SAVE = 4096;
    private static final int CLUSTER_GAP = 8;
    private static final int MAX_CLUSTERS = 24;

    private HiddenAttributeVariantAnalyzer() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] base = loadPayload(inputs.baseSave());
        Map<String, PlayerChange> requested = loadChanges(inputs.hiddenCsv());

        List<SaveIndex> saves = new ArrayList<>();
        LinkedHashSet<Integer> candidateOffsets = new LinkedHashSet<>();
        for (Map.Entry<String, PlayerChange> entry : requested.entrySet()) {
            Path save = inputs.saveDir().resolve("Trauner_" + entry.getKey() + "_only.fm");
            if (!Files.exists(save)) {
                continue;
            }
            byte[] payload = loadPayload(save);
            Alignment alignment = detectAlignment(base, payload);
            List<DiffRegion> regions = interestingRegions(base, payload, alignment);
            for (DiffRegion region : regions) {
                for (int offset = region.start(); offset < region.end(); offset++) {
                    candidateOffsets.add(offset);
                }
            }
            saves.add(new SaveIndex(entry.getKey(), entry.getValue(), save, alignment, payload.length));
        }

        Map<String, byte[]> payloadsBySave = new LinkedHashMap<>();
        for (SaveIndex save : saves) {
            payloadsBySave.put(save.attributeName(), loadPayload(save.save()));
        }

        List<VariableOffset> variableOffsets = inspectVariableOffsets(saves, payloadsBySave, new ArrayList<>(candidateOffsets));
        List<OffsetCluster> clusters = cluster(variableOffsets);
        System.out.println(renderJson(inputs, base.length, saves, candidateOffsets.size(), clusters));
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
            if (before[offset] != after[offset + alignment.shift()]) {
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

    private static List<VariableOffset> inspectVariableOffsets(
            List<SaveIndex> saves,
            Map<String, byte[]> payloadsBySave,
            List<Integer> candidateOffsets
    ) {
        List<VariableOffset> variableOffsets = new ArrayList<>();
        for (int offset : candidateOffsets) {
            Map<String, Integer> valuesBySave = new LinkedHashMap<>();
            Set<Integer> distinct = new LinkedHashSet<>();
            for (SaveIndex save : saves) {
                byte[] payload = payloadsBySave.get(save.attributeName());
                int shiftedOffset = offset + save.alignment().shift();
                if (shiftedOffset < 0 || shiftedOffset >= payload.length) {
                    continue;
                }
                int value = payload[shiftedOffset] & 0xFF;
                valuesBySave.put(save.attributeName(), value);
                distinct.add(value);
            }
            if (distinct.size() > 1) {
                variableOffsets.add(new VariableOffset(offset, new ArrayList<>(distinct), valuesBySave));
            }
        }
        variableOffsets.sort(Comparator
                .comparingInt(VariableOffset::distinctValueCount).reversed()
                .thenComparingInt(VariableOffset::offset));
        return variableOffsets;
    }

    private static List<OffsetCluster> cluster(List<VariableOffset> variableOffsets) {
        if (variableOffsets.isEmpty()) {
            return List.of();
        }
        List<OffsetCluster> clusters = new ArrayList<>();
        List<VariableOffset> current = new ArrayList<>();
        current.add(variableOffsets.getFirst());
        for (int i = 1; i < variableOffsets.size(); i++) {
            VariableOffset offset = variableOffsets.get(i);
            if (offset.offset() - current.getLast().offset() <= CLUSTER_GAP) {
                current.add(offset);
            } else {
                clusters.add(buildCluster(current));
                current = new ArrayList<>();
                current.add(offset);
            }
        }
        clusters.add(buildCluster(current));
        clusters.sort(Comparator
                .comparingInt(OffsetCluster::bestDistinctValueCount).reversed()
                .thenComparingInt(OffsetCluster::width)
                .thenComparingInt(OffsetCluster::start));
        return clusters.size() > MAX_CLUSTERS ? clusters.subList(0, MAX_CLUSTERS) : clusters;
    }

    private static OffsetCluster buildCluster(List<VariableOffset> offsets) {
        int start = offsets.getFirst().offset();
        int end = offsets.getLast().offset() + 1;
        int bestDistinct = offsets.stream().mapToInt(VariableOffset::distinctValueCount).max().orElse(0);
        return new OffsetCluster(start, end, offsets, bestDistinct);
    }

    private static String renderJson(
            Inputs inputs,
            int basePayloadSize,
            List<SaveIndex> saves,
            int candidateOffsetCount,
            List<OffsetCluster> clusters
    ) {
        StringBuilder json = new StringBuilder(24_000);
        json.append("{\n");
        field(json, "baseSave", quote(inputs.baseSave().toString()), true, true);
        field(json, "saveDir", quote(inputs.saveDir().toString()), true, true);
        field(json, "hiddenCsv", quote(inputs.hiddenCsv().toString()), true, true);
        field(json, "basePayloadSize", Integer.toString(basePayloadSize), true, true);
        field(json, "saveCount", Integer.toString(saves.size()), true, true);
        field(json, "candidateOffsetCount", Integer.toString(candidateOffsetCount), true, true);

        json.append("  \"clusters\": [\n");
        for (int i = 0; i < clusters.size(); i++) {
            OffsetCluster cluster = clusters.get(i);
            json.append("    {\n");
            field(json, "start", Integer.toString(cluster.start()), false, true);
            field(json, "end", Integer.toString(cluster.end()), false, true);
            field(json, "width", Integer.toString(cluster.width()), false, true);
            field(json, "offsetCount", Integer.toString(cluster.offsets().size()), false, true);
            field(json, "bestDistinctValueCount", Integer.toString(cluster.bestDistinctValueCount()), false, true);
            json.append("      \"offsets\": [\n");
            for (int j = 0; j < cluster.offsets().size(); j++) {
                VariableOffset variableOffset = cluster.offsets().get(j);
                json.append("        {\n");
                field(json, "offset", Integer.toString(variableOffset.offset()), false, true);
                field(json, "distinctValueCount", Integer.toString(variableOffset.distinctValueCount()), false, true);
                intListField(json, "distinctValues", variableOffset.distinctValues(), true);
                json.append("          \"valuesBySave\": {\n");
                int saveIndex = 0;
                for (Map.Entry<String, Integer> entry : variableOffset.valuesBySave().entrySet()) {
                    json.append("            ").append(quote(entry.getKey())).append(": ").append(entry.getValue());
                    if (++saveIndex < variableOffset.valuesBySave().size()) {
                        json.append(',');
                    }
                    json.append('\n');
                }
                json.append("          }\n");
                json.append("        }");
                if (j + 1 < cluster.offsets().size()) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            if (i + 1 < clusters.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private static void field(StringBuilder json, String name, String value, boolean topLevel, boolean trailingComma) {
        json.append(topLevel ? "  " : "        ")
                .append(quote(name))
                .append(": ")
                .append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void intListField(StringBuilder json, String name, List<Integer> values, boolean trailingComma) {
        json.append("          ").append(quote(name)).append(": [");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(", ");
            }
            json.append(values.get(i));
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
            throw new IllegalArgumentException("Usage: HiddenAttributeVariantAnalyzer <after.fm> <save_dir> <hidden.csv>");
        }
    }

    private record PlayerChange(String name, int from, int to) {
    }

    private record Alignment(int commonPrefix, int alignedStart, int shift) {
    }

    private record DiffRegion(int start, int end) {
        private int length() {
            return end - start;
        }
    }

    private record SaveIndex(String attributeName, PlayerChange change, Path save, Alignment alignment, int payloadSize) {
    }

    private record VariableOffset(int offset, List<Integer> distinctValues, Map<String, Integer> valuesBySave) {
        private int distinctValueCount() {
            return distinctValues.size();
        }
    }

    private record OffsetCluster(int start, int end, List<VariableOffset> offsets, int bestDistinctValueCount) {
        private int width() {
            return end - start;
        }
    }
}
