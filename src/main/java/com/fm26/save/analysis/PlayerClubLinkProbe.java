package com.fm26.save.analysis;

import com.fm26.save.analysis.GenericPlayerSubsetExtractor.ExtractedPlayer;
import com.fm26.save.analysis.GenericPlayerSubsetExtractor.ExtractionResult;
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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class PlayerClubLinkProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int SEARCH_MIN_DELTA = -4096;
    private static final int SEARCH_MAX_DELTA = 4096;

    private PlayerClubLinkProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length >= 1 ? Path.of(args[0]) : Path.of("games/Feyenoord_after.fm");
        Path csv = args.length >= 2 ? Path.of(args[1]) : Path.of("players_at_feyenoord.csv");

        byte[] payload = loadPayload(save);
        ExtractionResult extraction = GenericPlayerSubsetExtractor.extract(save);
        Map<Integer, ExtractedPlayer> extractedById = new HashMap<>();
        for (ExtractedPlayer player : extraction.players()) {
            extractedById.put(player.id(), player);
        }

        List<ClubRow> rows = loadRows(csv);
        List<ClubRow> matched = rows.stream()
                .filter(row -> extractedById.containsKey(row.playerId()))
                .toList();

        Map<Integer, Integer> allCounts = new HashMap<>();
        Map<Integer, Integer> loanCounts = new HashMap<>();
        Map<Integer, List<String>> examples = new HashMap<>();
        Map<Integer, Integer> exactCellMatches = new HashMap<>();

        for (ClubRow row : matched) {
            ExtractedPlayer player = extractedById.get(row.playerId());
            int personPair = player.personPair();
            for (int delta = SEARCH_MIN_DELTA; delta <= SEARCH_MAX_DELTA; delta++) {
                int offset = personPair + delta;
                if (offset < 0 || offset + 4 > payload.length) {
                    continue;
                }
                if (u32le(payload, offset) != row.clubId()) {
                    continue;
                }
                allCounts.merge(delta, 1, Integer::sum);
                if (row.clubId() != 1013) {
                    loanCounts.merge(delta, 1, Integer::sum);
                }
                examples.computeIfAbsent(delta, ignored -> new ArrayList<>());
                List<String> sample = examples.get(delta);
                if (sample.size() < 5) {
                    sample.add(row.playerId() + ":" + row.name() + "->" + row.clubId() + "@" + offset);
                }
                if (payload[offset - 1 >= 0 ? offset - 1 : offset] == 0) {
                    exactCellMatches.merge(delta, 1, Integer::sum);
                }
            }
        }

        List<Integer> ranked = allCounts.keySet().stream()
                .sorted(Comparator
                        .comparingInt((Integer delta) -> loanCounts.getOrDefault(delta, 0)).reversed()
                        .thenComparingInt(delta -> allCounts.getOrDefault(delta, 0)).reversed()
                        .thenComparingInt(Math::abs))
                .toList();

        StringBuilder out = new StringBuilder(16384);
        out.append("{\n");
        field(out, 2, "save", quote(save.toString()), true);
        field(out, 2, "csv", quote(csv.toString()), true);
        field(out, 2, "matchedRows", Integer.toString(matched.size()), true);
        out.append("  \"topDeltas\": [\n");
        int emitted = 0;
        for (Integer delta : ranked) {
            if (emitted == 20) {
                break;
            }
            out.append("    {\n");
            field(out, 6, "delta", Integer.toString(delta), true);
            field(out, 6, "allMatches", Integer.toString(allCounts.getOrDefault(delta, 0)), true);
            field(out, 6, "loanMatches", Integer.toString(loanCounts.getOrDefault(delta, 0)), true);
            field(out, 6, "zeroPrefixedMatches", Integer.toString(exactCellMatches.getOrDefault(delta, 0)), true);
            field(out, 6, "examples", stringArray(examples.getOrDefault(delta, List.of())), false);
            out.append("    }");
            emitted++;
            if (emitted < Math.min(20, ranked.size())) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("  ]\n");
        out.append("}\n");
        System.out.print(out);
    }

    private static List<ClubRow> loadRows(Path csv) throws IOException {
        List<ClubRow> rows = new ArrayList<>();
        List<String> lines = Files.readAllLines(csv);
        boolean first = true;
        for (String line : lines) {
            if (first) {
                first = false;
                continue;
            }
            if (line == null || line.isBlank()) {
                continue;
            }
            String[] parts = line.split(",", -1);
            if (parts.length < 4) {
                continue;
            }
            rows.add(new ClubRow(
                    Integer.parseUnsignedInt(parts[0].trim()),
                    parts[1].trim(),
                    parts[2].trim(),
                    Integer.parseUnsignedInt(parts[3].trim())
            ));
        }
        return rows;
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

    private static InputStream skipFully(InputStream in, int bytes) throws IOException {
        long remaining = bytes;
        while (remaining > 0) {
            long skipped = in.skip(remaining);
            if (skipped <= 0) {
                if (in.read() < 0) {
                    throw new IOException("Unexpected EOF while skipping header");
                }
                skipped = 1;
            }
            remaining -= skipped;
        }
        return in;
    }

    private static int u32le(byte[] payload, int offset) {
        return (payload[offset] & 0xFF)
                | ((payload[offset + 1] & 0xFF) << 8)
                | ((payload[offset + 2] & 0xFF) << 16)
                | ((payload[offset + 3] & 0xFF) << 24);
    }

    private static void field(StringBuilder out, int indent, String key, String value, boolean trailingComma) {
        out.append(" ".repeat(indent))
                .append(quote(key))
                .append(": ")
                .append(value);
        if (trailingComma) {
            out.append(',');
        }
        out.append('\n');
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> out.append(c);
            }
        }
        out.append('"');
        return out.toString();
    }

    private static String stringArray(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(quote(Objects.toString(values.get(i), "")));
        }
        out.append(']');
        return out.toString();
    }

    private record ClubRow(int playerId, String name, String clubName, int clubId) {
    }
}
