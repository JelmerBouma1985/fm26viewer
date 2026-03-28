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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class ClubMembershipProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW = 16384;

    private ClubMembershipProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length >= 1 ? Path.of(args[0]) : Path.of("games/Feyenoord_after.fm");
        Path csv = args.length >= 2 ? Path.of(args[1]) : Path.of("players_at_feyenoord.csv");
        byte[] payload = loadPayload(save);

        List<Row> rows = loadRows(csv);
        Map<Integer, List<Row>> byClub = new LinkedHashMap<>();
        for (Row row : rows) {
            byClub.computeIfAbsent(row.clubId(), ignored -> new ArrayList<>()).add(row);
        }

        StringBuilder out = new StringBuilder(32768);
        out.append("{\n");
        field(out, 2, "save", quote(save.toString()), true);
        field(out, 2, "csv", quote(csv.toString()), true);
        out.append("  \"clubs\": {\n");
        int clubRendered = 0;
        List<Integer> clubIds = byClub.keySet().stream().sorted().toList();
        for (int clubId : clubIds) {
            List<Row> members = byClub.get(clubId);
            List<Candidate> candidates = new ArrayList<>();
            for (int offset = 0; offset + 4 <= payload.length; offset++) {
                if (u32le(payload, offset) != clubId) {
                    continue;
                }
                Set<Integer> nearbyMembers = new LinkedHashSet<>();
                List<String> examples = new ArrayList<>();
                int start = Math.max(0, offset - WINDOW);
                int end = Math.min(payload.length - 4, offset + WINDOW);
                for (Row row : members) {
                    List<Integer> refs = findRefs(payload, start, end, row.playerId());
                    if (!refs.isEmpty()) {
                        nearbyMembers.add(row.playerId());
                        if (examples.size() < 6) {
                            examples.add(row.playerId() + ":" + row.name() + "@" + refs.get(0));
                        }
                    }
                }
                if (!nearbyMembers.isEmpty()) {
                    candidates.add(new Candidate(offset, nearbyMembers.size(), examples));
                }
            }
            candidates.sort(Comparator.comparingInt(Candidate::memberHits).reversed()
                    .thenComparingInt(Candidate::offset));

            out.append("    ").append(quote(Integer.toString(clubId))).append(": {\n");
            field(out, 6, "memberCount", Integer.toString(members.size()), true);
            field(out, 6, "topCandidates", renderCandidates(candidates), false);
            out.append("    }");
            clubRendered++;
            if (clubRendered < clubIds.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("  }\n");
        out.append("}\n");
        System.out.print(out);
    }

    private static String renderCandidates(List<Candidate> candidates) {
        StringBuilder out = new StringBuilder("[");
        int limit = Math.min(10, candidates.size());
        for (int i = 0; i < limit; i++) {
            Candidate candidate = candidates.get(i);
            if (i > 0) {
                out.append(", ");
            }
            out.append("{\"offset\":").append(candidate.offset())
                    .append(",\"memberHits\":").append(candidate.memberHits())
                    .append(",\"examples\":").append(stringArray(candidate.examples()))
                    .append("}");
        }
        out.append("]");
        return out.toString();
    }

    private static List<Integer> findRefs(byte[] payload, int start, int end, int value) {
        List<Integer> refs = new ArrayList<>();
        for (int offset = start; offset <= end; offset++) {
            if (u32le(payload, offset) == value) {
                refs.add(offset);
            }
        }
        return refs;
    }

    private static List<Row> loadRows(Path csv) throws IOException {
        List<Row> rows = new ArrayList<>();
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
            rows.add(new Row(
                    Integer.parseUnsignedInt(parts[0].trim()),
                    parts[1].trim(),
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

    private static String stringArray(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(quote(values.get(i)));
        }
        out.append(']');
        return out.toString();
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record Row(int playerId, String name, int clubId) {
    }

    private record Candidate(int offset, int memberHits, List<String> examples) {
    }
}
