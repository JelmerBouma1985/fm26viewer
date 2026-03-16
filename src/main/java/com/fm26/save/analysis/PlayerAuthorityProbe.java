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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class PlayerAuthorityProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int SEARCH_RADIUS = 25_000;
    private static final int CLUSTER_GAP = 16;

    private PlayerAuthorityProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path baseSave = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);
        byte[] basePayload = loadPayload(baseSave);

        List<PlayerConfig> configs = List.of(
                new PlayerConfig("Smal", "Small_", 37_060_899),
                new PlayerConfig("Kooistra", "Kooistra_", 2_000_304_951),
                new PlayerConfig("Aidoo", "Aidoo_", 13_158_416)
        );

        StringBuilder json = new StringBuilder(131072);
        json.append("{\n");
        field(json, 2, "baseSave", quote(baseSave.toString()), true);
        json.append("  \"players\": {\n");
        int rendered = 0;
        for (PlayerConfig config : configs) {
            Integer basePersonPair = findPersonPair(basePayload, config.playerId());
            List<Path> saves = findPlayerSaves(config.prefix());
            json.append("    ").append(quote(config.name())).append(": {\n");
            field(json, 6, "playerId", Integer.toUnsignedString(config.playerId()), true);
            field(json, 6, "basePersonPair", basePersonPair == null ? "null" : Integer.toString(basePersonPair), true);
            field(json, 6, "saveCount", Integer.toString(saves.size()), true);
            field(json, 6, "clusters", basePersonPair == null ? "[]" : renderClusters(basePayload, basePersonPair, saves, config.playerId()), false);
            json.append("    }");
            rendered++;
            if (rendered < configs.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n");
        json.append("}\n");
        System.out.print(json);
    }

    private static String renderClusters(byte[] basePayload, int basePersonPair, List<Path> saves, int playerId) throws IOException {
        Map<Integer, Set<String>> relativeOffsets = new LinkedHashMap<>();
        for (Path save : saves) {
            byte[] payload = loadPayload(save);
            Integer targetPersonPair = findPersonPair(payload, playerId);
            if (targetPersonPair == null) {
                continue;
            }
            int start = Math.max(-SEARCH_RADIUS, -basePersonPair);
            int end = Math.min(SEARCH_RADIUS, Math.min(basePayload.length - basePersonPair, payload.length - targetPersonPair) - 1);
            for (int rel = start; rel <= end; rel++) {
                if (basePayload[basePersonPair + rel] != payload[targetPersonPair + rel]) {
                    relativeOffsets.computeIfAbsent(rel, ignored -> new LinkedHashSet<>()).add(save.getFileName().toString());
                }
            }
        }

        List<Cluster> clusters = cluster(relativeOffsets);
        clusters.sort(Comparator.comparingInt(Cluster::saveCount).reversed().thenComparingInt(Cluster::length).reversed());

        StringBuilder out = new StringBuilder();
        out.append("[\n");
        for (int i = 0; i < clusters.size() && i < 20; i++) {
            Cluster cluster = clusters.get(i);
            out.append("        {\n");
            field(out, 10, "startRelative", Integer.toString(cluster.start()), true);
            field(out, 10, "endRelative", Integer.toString(cluster.end()), true);
            field(out, 10, "length", Integer.toString(cluster.length()), true);
            field(out, 10, "saveCount", Integer.toString(cluster.saveCount()), true);
            field(out, 10, "saves", stringArray(cluster.saves()), false);
            out.append("        }");
            if (i + 1 < clusters.size() && i + 1 < 20) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("      ]");
        return out.toString();
    }

    private static List<Cluster> cluster(Map<Integer, Set<String>> relativeOffsets) {
        List<Integer> sorted = relativeOffsets.keySet().stream().sorted().toList();
        List<Cluster> clusters = new ArrayList<>();
        if (sorted.isEmpty()) {
            return clusters;
        }
        int start = sorted.get(0);
        int end = start;
        Set<String> saves = new LinkedHashSet<>(relativeOffsets.get(start));
        for (int i = 1; i < sorted.size(); i++) {
            int rel = sorted.get(i);
            if (rel - end <= CLUSTER_GAP) {
                end = rel;
                saves.addAll(relativeOffsets.get(rel));
                continue;
            }
            clusters.add(new Cluster(start, end, new LinkedHashSet<>(saves)));
            start = rel;
            end = rel;
            saves.clear();
            saves.addAll(relativeOffsets.get(rel));
        }
        clusters.add(new Cluster(start, end, new LinkedHashSet<>(saves)));
        return clusters;
    }

    private static List<Path> findPlayerSaves(String prefix) throws IOException {
        try (var stream = Files.list(Path.of("games"))) {
            return stream
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().startsWith(prefix))
                    .filter(path -> path.getFileName().toString().endsWith(".fm"))
                    .sorted()
                    .toList();
        }
    }

    private static Integer findPersonPair(byte[] payload, int playerId) {
        byte b0 = (byte) (playerId & 0xFF);
        byte b1 = (byte) ((playerId >>> 8) & 0xFF);
        byte b2 = (byte) ((playerId >>> 16) & 0xFF);
        byte b3 = (byte) ((playerId >>> 24) & 0xFF);
        for (int offset = 0; offset + 8 <= payload.length && offset < PERSON_BLOCK_MAX_OFFSET; offset++) {
            if (payload[offset] == b0
                    && payload[offset + 1] == b1
                    && payload[offset + 2] == b2
                    && payload[offset + 3] == b3
                    && payload[offset + 4] == b0
                    && payload[offset + 5] == b1
                    && payload[offset + 6] == b2
                    && payload[offset + 7] == b3) {
                return offset;
            }
        }
        return null;
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

    private static void field(StringBuilder json, int indent, String name, String value, boolean comma) {
        json.append(" ".repeat(indent)).append(quote(name)).append(": ").append(value);
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String stringArray(Set<String> values) {
        StringBuilder out = new StringBuilder("[");
        int index = 0;
        for (String value : values) {
            if (index++ > 0) {
                out.append(", ");
            }
            out.append(quote(value));
        }
        return out.append(']').toString();
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record PlayerConfig(String name, String prefix, int playerId) {
    }

    private record Cluster(int start, int end, Set<String> saves) {
        private int length() {
            return end - start + 1;
        }

        private int saveCount() {
            return saves.size();
        }
    }
}
