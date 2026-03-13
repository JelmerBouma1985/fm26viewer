package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdInputStream;
import com.github.luben.zstd.ZstdIOException;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class PlayerSaveDiffAnalyzer {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_SIZE = 1024;
    private static final int WINDOW_STEP = 16;
    private static final int SEARCH_AHEAD = 8_192;
    private static final int MERGE_GAP = 32;
    private static final int CONTEXT = 48;
    private static final HexFormat HEX = HexFormat.ofDelimiter(" ");

    private PlayerSaveDiffAnalyzer() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] before = loadPayload(inputs.beforeSave());
        byte[] after = loadPayload(inputs.afterSave());

        Alignment alignment = detectAlignment(before, after);
        List<DiffRegion> regions = diffRegions(before, after, alignment);
        List<PlayerChange> changes = loadChanges(inputs.changesCsv());
        Map<DiffRegion, List<String>> correlated = correlateRegions(before, after, alignment, regions, changes);

        printReport(inputs, before, after, alignment, regions, correlated);
    }

    private static byte[] loadPayload(Path path) throws IOException {
        if (!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".fm")) {
            return Files.readAllBytes(path);
        }
        byte[] compressed = Files.readAllBytes(path);
        if (compressed.length <= FMF_ZSTD_OFFSET) {
            throw new IOException("File is too small to contain an FMF wrapper: " + path);
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

    private static List<DiffRegion> diffRegions(byte[] before, byte[] after, Alignment alignment) {
        List<DiffRegion> raw = new ArrayList<>();
        int shiftedStart = alignment.alignedStart();
        int shift = alignment.shift();
        int limit = Math.min(before.length, after.length - shift);
        int regionStart = -1;
        for (int i = shiftedStart; i < limit; i++) {
            if (before[i] != after[i + shift]) {
                if (regionStart < 0) {
                    regionStart = i;
                }
            } else if (regionStart >= 0) {
                raw.add(new DiffRegion(regionStart, i));
                regionStart = -1;
            }
        }
        if (regionStart >= 0) {
            raw.add(new DiffRegion(regionStart, limit));
        }

        List<DiffRegion> merged = new ArrayList<>();
        for (DiffRegion region : raw) {
            if (merged.isEmpty()) {
                merged.add(region);
                continue;
            }
            DiffRegion previous = merged.getLast();
            if (region.start() - previous.end() < MERGE_GAP) {
                merged.set(merged.size() - 1, new DiffRegion(previous.start(), region.end()));
            } else {
                merged.add(region);
            }
        }
        return merged;
    }

    private static List<PlayerChange> loadChanges(Path csv) throws IOException {
        List<PlayerChange> changes = new ArrayList<>();
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        if (lines.isEmpty()) {
            return changes;
        }
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split(",", 3);
            if (parts.length != 3) {
                throw new IOException("Invalid CSV row: " + line);
            }
            changes.add(new PlayerChange(parts[0], Integer.parseInt(parts[1]), Integer.parseInt(parts[2])));
        }
        return changes;
    }

    private static Map<DiffRegion, List<String>> correlateRegions(
            byte[] before,
            byte[] after,
            Alignment alignment,
            List<DiffRegion> regions,
            List<PlayerChange> changes
    ) {
        Map<DiffRegion, List<String>> correlated = new LinkedHashMap<>();
        for (DiffRegion region : regions) {
            byte[] beforeSlice = slice(before, region.start() - 8, region.end() + 8);
            byte[] afterSlice = slice(after, region.start() + alignment.shift() - 8, region.end() + alignment.shift() + 8);
            List<String> matches = new ArrayList<>();
            for (PlayerChange change : changes) {
                if (matchesHeuristically(beforeSlice, afterSlice, change)) {
                    matches.add(change.name() + " " + change.from() + " -> " + change.to());
                }
            }
            correlated.put(region, matches);
        }
        return correlated;
    }

    private static boolean matchesHeuristically(byte[] before, byte[] after, PlayerChange change) {
        return containsConverted(before, change.from()) && containsConverted(after, change.to());
    }

    private static boolean containsConverted(byte[] bytes, int value) {
        if (value >= 0 && value < 256 && contains(bytes, (byte) value)) {
            return true;
        }
        if (value >= 0 && value < 65_536) {
            byte lo = (byte) (value & 0xFF);
            byte hi = (byte) ((value >>> 8) & 0xFF);
            if (contains(bytes, lo, hi)) {
                return true;
            }
        }
        return contains(bytes,
                (byte) (value & 0xFF),
                (byte) ((value >>> 8) & 0xFF),
                (byte) ((value >>> 16) & 0xFF),
                (byte) ((value >>> 24) & 0xFF));
    }

    private static boolean contains(byte[] bytes, byte... pattern) {
        if (pattern.length == 0 || bytes.length < pattern.length) {
            return false;
        }
        for (int i = 0; i <= bytes.length - pattern.length; i++) {
            boolean matches = true;
            for (int j = 0; j < pattern.length; j++) {
                if (bytes[i + j] != pattern[j]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return true;
            }
        }
        return false;
    }

    private static byte[] slice(byte[] bytes, int from, int to) {
        int start = Math.max(0, from);
        int end = Math.min(bytes.length, to);
        if (end <= start) {
            return new byte[0];
        }
        byte[] copy = new byte[end - start];
        System.arraycopy(bytes, start, copy, 0, copy.length);
        return copy;
    }

    private static void printReport(
            Inputs inputs,
            byte[] before,
            byte[] after,
            Alignment alignment,
            List<DiffRegion> regions,
            Map<DiffRegion, List<String>> correlated
    ) {
        System.out.println("# Player Save Diff Report");
        System.out.println();
        System.out.println("before_save=" + inputs.beforeSave());
        System.out.println("after_save=" + inputs.afterSave());
        System.out.println("changes_csv=" + inputs.changesCsv());
        System.out.println("before_size=" + before.length);
        System.out.println("after_size=" + after.length);
        System.out.println("common_prefix=" + alignment.prefixLength());
        System.out.println("aligned_start=" + alignment.alignedStart());
        System.out.println("shift=" + alignment.shift());
        System.out.println("region_count=" + regions.size());
        System.out.println();

        List<Map.Entry<DiffRegion, List<String>>> interesting = correlated.entrySet().stream()
                .filter(entry -> !entry.getValue().isEmpty())
                .sorted(Comparator.<Map.Entry<DiffRegion, List<String>>>comparingInt(entry -> -entry.getValue().size())
                        .thenComparingInt(entry -> entry.getKey().length()))
                .toList();

        System.out.println("## Correlated Regions");
        if (interesting.isEmpty()) {
            System.out.println("No diff regions correlated with CSV values using byte-level heuristics.");
        }
        for (Map.Entry<DiffRegion, List<String>> entry : interesting) {
            printRegion(entry.getKey(), alignment.shift(), before, after, entry.getValue());
        }

        System.out.println("## Largest Regions");
        regions.stream()
                .sorted(Comparator.comparingInt(DiffRegion::length).reversed())
                .limit(10)
                .forEach(region -> printRegion(region, alignment.shift(), before, after, correlated.getOrDefault(region, List.of())));
    }

    private static void printRegion(DiffRegion region, int shift, byte[] before, byte[] after, List<String> matches) {
        System.out.println();
        System.out.println("region=" + region.start() + "-" + region.end() + " len=" + region.length());
        if (!matches.isEmpty()) {
            System.out.println("csv_matches=" + String.join("; ", matches));
        }
        int beforeStart = Math.max(0, region.start() - CONTEXT);
        int beforeEnd = Math.min(before.length, region.end() + CONTEXT);
        int afterStart = Math.max(0, beforeStart + shift);
        int afterEnd = Math.min(after.length, beforeEnd + shift);
        byte[] beforeSlice = slice(before, beforeStart, beforeEnd);
        byte[] afterSlice = slice(after, afterStart, afterEnd);
        System.out.println("before_hex=" + HEX.formatHex(beforeSlice));
        System.out.println("after_hex =" + HEX.formatHex(afterSlice));
        System.out.println("before_ascii=" + ascii(beforeSlice));
        System.out.println("after_ascii =" + ascii(afterSlice));
    }

    private static String ascii(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length);
        for (byte value : bytes) {
            int unsigned = value & 0xFF;
            if (unsigned >= 32 && unsigned <= 126) {
                builder.append((char) unsigned);
            } else {
                builder.append('.');
            }
        }
        return builder.toString();
    }

    private record Inputs(Path beforeSave, Path afterSave, Path changesCsv) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 3) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]));
            }
            if (args.length == 0) {
                return new Inputs(
                        Path.of("games/Feyenoord_before.fm"),
                        Path.of("games/Feyenoord_after.fm"),
                        Path.of("gernot_trauner_changes.csv")
                );
            }
            throw new IllegalArgumentException("Usage: PlayerSaveDiffAnalyzer <before.fm> <after.fm> <changes.csv>");
        }
    }

    private record Alignment(int prefixLength, int alignedStart, int shift) {
    }

    private record DiffRegion(int start, int end) {
        private DiffRegion {
            Objects.checkFromToIndex(start, end, Integer.MAX_VALUE);
        }

        private int length() {
            return end - start;
        }
    }

    private record PlayerChange(String name, int from, int to) {
        private PlayerChange {
            name = name.toLowerCase(Locale.ROOT);
        }
    }
}
