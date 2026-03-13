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

public final class TraunerGeneralDiffProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_SIZE = 1024;
    private static final int WINDOW_STEP = 16;
    private static final int SEARCH_AHEAD = 8192;
    private static final int MERGE_GAP = 32;
    private static final int CONTEXT = 48;
    private static final int MAX_REGIONS = 32;

    private TraunerGeneralDiffProbe() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        Map<String, PlayerChange> changes = loadChanges(inputs.generalCsv());
        byte[] base = loadPayload(inputs.baseSave());

        List<ProbeResult> results = new ArrayList<>();
        for (Map.Entry<String, PlayerChange> entry : changes.entrySet()) {
            Path save = inputs.saveDir().resolve("Trauner_" + slug(entry.getKey()) + "_only.fm");
            if (!Files.exists(save)) {
                continue;
            }
            byte[] target = loadPayload(save);
            Alignment alignment = detectAlignment(base, target);
            List<DiffRegion> regions = diffRegions(base, target, alignment);
            results.add(new ProbeResult(entry.getKey(), entry.getValue(), save, alignment, summarize(base, target, alignment, regions)));
        }

        System.out.println(renderJson(inputs, base.length, results));
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

    private static String slug(String attribute) {
        return attribute.toLowerCase(Locale.ROOT).replace(' ', '_');
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
        int limit = Math.min(before.length, after.length - alignment.shift());
        int regionStart = -1;
        for (int i = alignment.alignedStart(); i < limit; i++) {
            if (before[i] != after[i + alignment.shift()]) {
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
            DiffRegion previous = merged.get(merged.size() - 1);
            if (region.start() - previous.end() < MERGE_GAP) {
                merged.set(merged.size() - 1, new DiffRegion(previous.start(), region.end()));
            } else {
                merged.add(region);
            }
        }
        return merged;
    }

    private static List<RegionSummary> summarize(byte[] base, byte[] target, Alignment alignment, List<DiffRegion> regions) {
        return regions.stream()
                .sorted(Comparator.comparingInt(DiffRegion::length).thenComparingInt(DiffRegion::start))
                .limit(MAX_REGIONS)
                .map(region -> new RegionSummary(
                        region.start(),
                        region.end(),
                        region.length(),
                        hex(slice(base, region.start() - CONTEXT, region.end() + CONTEXT)),
                        hex(slice(target, region.start() + alignment.shift() - CONTEXT, region.end() + alignment.shift() + CONTEXT))
                ))
                .toList();
    }

    private static byte[] slice(byte[] bytes, int from, int to) {
        int start = Math.max(0, from);
        int end = Math.min(bytes.length, to);
        byte[] copy = new byte[Math.max(0, end - start)];
        if (copy.length > 0) {
            System.arraycopy(bytes, start, copy, 0, copy.length);
        }
        return copy;
    }

    private static String renderJson(Inputs inputs, int baseSize, List<ProbeResult> results) {
        StringBuilder json = new StringBuilder(32000);
        json.append("{\n");
        field(json, "baseSave", quote(inputs.baseSave().toString()), true, true);
        field(json, "generalCsv", quote(inputs.generalCsv().toString()), true, true);
        field(json, "saveDir", quote(inputs.saveDir().toString()), true, true);
        field(json, "baseSize", Integer.toString(baseSize), true, true);
        json.append("  \"results\": [\n");
        for (int i = 0; i < results.size(); i++) {
            ProbeResult result = results.get(i);
            json.append("    {\n");
            field(json, "attribute", quote(result.attribute()), false, true);
            field(json, "save", quote(result.save().toString()), false, true);
            field(json, "from", Integer.toString(result.change().from()), false, true);
            field(json, "to", Integer.toString(result.change().to()), false, true);
            field(json, "shift", Integer.toString(result.alignment().shift()), false, true);
            field(json, "regionCount", Integer.toString(result.regions().size()), false, true);
            json.append("      \"regions\": [\n");
            for (int j = 0; j < result.regions().size(); j++) {
                RegionSummary region = result.regions().get(j);
                json.append("        {\n");
                field(json, "start", Integer.toString(region.start()), false, true);
                field(json, "end", Integer.toString(region.end()), false, true);
                field(json, "length", Integer.toString(region.length()), false, true);
                field(json, "beforeHex", quote(region.beforeHex()), false, true);
                field(json, "afterHex", quote(region.afterHex()), false, false);
                json.append("        }");
                if (j + 1 < result.regions().size()) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            if (i + 1 < results.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private static void field(StringBuilder json, String name, String value, boolean topLevelIndent, boolean trailingComma) {
        json.append(topLevelIndent ? "  " : "      ");
        json.append(quote(name)).append(": ").append(value);
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

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                builder.append(' ');
            }
            builder.append(String.format(Locale.ROOT, "%02x", bytes[i] & 0xFF));
        }
        return builder.toString();
    }

    private record Inputs(Path baseSave, Path generalCsv, Path saveDir) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 3) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]));
            }
            return new Inputs(Path.of("games/Feyenoord_after.fm"), Path.of("general.csv"), Path.of("games"));
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

    private record RegionSummary(int start, int end, int length, String beforeHex, String afterHex) {
    }

    private record ProbeResult(String attribute, PlayerChange change, Path save, Alignment alignment, List<RegionSummary> regions) {
    }
}
