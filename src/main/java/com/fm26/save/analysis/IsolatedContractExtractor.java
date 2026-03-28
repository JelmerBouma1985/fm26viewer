package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class IsolatedContractExtractor {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int SEARCH_RADIUS = 1_000;

    private IsolatedContractExtractor() {
    }

    public static void main(String[] args) throws Exception {
        byte[] payload = loadPayload(Path.of("games/Feyenoord_after.fm"));
        PreparedPayload prepared = prepare(payload);
        Map<Integer, String> players = new LinkedHashMap<>();
        players.put(16_023_929, "Trauner");
        players.put(37_060_899, "Smal");
        players.put(653_054, "Modric");
        players.put(2_000_040_347, "Pablo Torre");
        players.put(37_021_992, "Player37021992");
        players.put(2_000_259_904, "Player2000259904");

        StringBuilder out = new StringBuilder(32768);
        out.append("{\n");
        int rendered = 0;
        for (Map.Entry<Integer, String> entry : players.entrySet()) {
            Extraction extraction = extract(prepared, entry.getKey());
            out.append("  ").append(quote(entry.getValue())).append(": ");
            out.append(renderExtraction(extraction));
            if (++rendered < players.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("}\n");
        System.out.print(out);
    }

    public static Extraction extract(byte[] payload, int playerId) {
        return extract(prepare(payload), playerId);
    }

    public static PreparedPayload prepare(byte[] payload) {
        Map<Integer, List<Integer>> pairedHitsById = new HashMap<>();
        for (int off = 0; off + 8 <= payload.length; off++) {
            int left = u32le(payload, off);
            if (left == 0 || left == -1) {
                continue;
            }
            if (u32le(payload, off + 4) != left) {
                continue;
            }
            pairedHitsById.computeIfAbsent(left, ignored -> new ArrayList<>()).add(off);
        }
        return new PreparedPayload(payload, pairedHitsById, new HashMap<>());
    }

    public static Extraction extract(PreparedPayload prepared, int playerId) {
        byte[] payload = prepared.payload();
        List<Integer> pairedHits = prepared.pairedHitsById().getOrDefault(playerId, List.of());
        List<ClusterCandidate> candidates = new ArrayList<>();
        for (int hit : pairedHits) {
            ClusterCandidate candidate = prepared.clusterCache().computeIfAbsent(hit, ignored -> analyzeCluster(payload, hit));
            if (candidate != null) {
                candidates.add(candidate);
            }
        }
        ClusterCandidate best = candidates.stream()
                .max(Comparator
                        .comparingInt(ClusterCandidate::familyPriority)
                        .thenComparingInt(ClusterCandidate::score))
                .orElse(null);
        return new Extraction(playerId, pairedHits, candidates, best);
    }

    private static ClusterCandidate analyzeCluster(byte[] payload, int anchor) {
        List<DateRow> dateRows = findDateRows(payload, anchor);
        List<Row> salaryRows = findSalaryRows(payload, anchor);

        if (salaryRows.isEmpty() && dateRows.isEmpty()) {
            return null;
        }

        PairSelection pairSelection = pickBestPair(payload, anchor, dateRows, salaryRows);
        DateRow bestDate = pairSelection.date;
        Row bestSalary = pairSelection.salary;

        int familyPriority = 1;
        int score = 0;
        if (bestSalary != null) {
            score += bestSalary.score;
        }
        if (bestDate != null) {
            score += bestDate.score;
        }

        if (bestSalary != null && bestDate != null) {
            int gap = Math.abs(bestSalary.rel - bestDate.rel);
            if (gap <= 80) {
                score += 20;
                familyPriority = 3; // compact primary family
            } else if (gap <= 420) {
                score += 12;
                familyPriority = 2; // linked family
            }
        }

        // Header-shaped rows boost confidence for both families.
        int headerCount = countHeaderRows(payload, anchor);
        score += Math.min(headerCount, 4) * 2;

        return new ClusterCandidate(
                anchor,
                familyPriority,
                score,
                headerCount,
                bestSalary,
                bestDate);
    }

    private static PairSelection pickBestPair(byte[] payload, int anchor, List<DateRow> dateRows, List<Row> salaryRows) {
        Row preferredNegativeSalary = salaryRows.stream()
                .filter(row -> row.rel < 0)
                .sorted(Comparator
                        .comparingInt((Row row) -> -row.score)
                        .thenComparingInt(row -> Math.abs(row.rel)))
                .findFirst()
                .orElse(null);
        DateRow bestDate = null;
        Row bestSalary = null;
        int bestScore = Integer.MIN_VALUE;
        for (DateRow dateRow : dateRows) {
            Row anchored = findAnchoredSalary(payload, anchor, dateRow.rel);
            int pairScore = dateRow.score;
            if (anchored != null) {
                pairScore += anchored.score + 20;
                if (dateRow.rel < 0) {
                    pairScore += 8;
                }
                if (anchored.rel < 0) {
                    pairScore += 8;
                }
            }
            if (pairScore > bestScore) {
                bestScore = pairScore;
                bestDate = dateRow;
                bestSalary = anchored;
            }
        }
        if (bestDate != null) {
            return new PairSelection(bestDate, preferredNegativeSalary != null ? preferredNegativeSalary : bestSalary);
        }
        Row fallbackSalary = salaryRows.stream()
                .sorted(Comparator
                        .comparingInt((Row row) -> row.rel < 0 ? 0 : 1)
                        .thenComparingInt(row -> -row.score))
                .findFirst()
                .orElse(null);
        if (fallbackSalary == null) {
            fallbackSalary = salaryRows.stream()
                .max(Comparator.comparingInt(row -> row.score))
                .orElse(null);
        }
        return new PairSelection(dateRows.stream().max(Comparator.comparingInt(row -> row.score)).orElse(null), fallbackSalary);
    }

    private static Row findAnchoredSalary(byte[] payload, int anchor, int dateRel) {
        for (int delta = 52; delta <= 60; delta++) {
            int rel = dateRel + delta;
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int value = u32le(payload, off);
            if (value > 0 && value <= 5_000_000
                    && payload[off + 4] == 0x01
                    && payload[off + 5] == 0x0b
                    && payload[off + 6] == 0x00
                    && payload[off + 7] == (byte) 0xff
                    && payload[off + 8] == (byte) 0xff
                    && payload[off + 9] == (byte) 0xff
                    && payload[off + 10] == (byte) 0xff) {
                return new Row(rel, value, 30, hex(payload, off, 16));
            }
        }
        return null;
    }

    private static int countHeaderRows(byte[] payload, int anchor) {
        int count = 0;
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 16; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            if (isHeaderLike(payload, off)) {
                count++;
            }
        }
        return count;
    }

    private static List<Row> findSalaryRows(byte[] payload, int anchor) {
        List<Row> rows = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 16; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int value = u32le(payload, off);
            if (value > 0 && value <= 5_000_000
                    && payload[off + 4] == 0x01
                    && payload[off + 5] == 0x0b
                    && payload[off + 6] == 0x00
                    && payload[off + 7] == (byte) 0xff
                    && payload[off + 8] == (byte) 0xff
                    && payload[off + 9] == (byte) 0xff
                    && payload[off + 10] == (byte) 0xff) {
                int score = 10;
                if (value >= 1_000) {
                    score += 4;
                }
                if (value <= 1_500_000) {
                    score += 4;
                }
                rows.add(new Row(rel, value, score, hex(payload, off, 16)));
            }
        }
        return rows;
    }

    private static List<DateRow> findDateRows(byte[] payload, int anchor) {
        List<DateRow> rows = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 16; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int ordinal1 = u16le(payload, off);
            int year1 = u16le(payload, off + 2);
            int ordinal2 = u16le(payload, off + 4);
            int year2 = u16le(payload, off + 6);
            int marker1 = u16le(payload, off + 8);
            int marker2 = u16le(payload, off + 10);

            if (ordinal1 >= 0x0070 && ordinal1 <= 0x01ff
                    && year1 >= 0x07e0 && year1 <= 0x07f8
                    && ordinal2 >= 0x0070 && ordinal2 <= 0x3000
                    && year2 >= 0x07e0 && year2 <= 0x07f8
                    && marker1 <= 0x0040
                    && marker2 <= 0x5000) {
                LocalDate date = decodeDate(ordinal1, year1);
                int score = 10;
                if (date != null) {
                    score += 6;
                }
                if (looksLikeContractHeaderBefore(payload, anchor + rel)) {
                    score += 8;
                }
                rows.add(new DateRow(rel, score, hex(payload, off, 16), ordinal1, year1, date));
            }
        }
        return rows;
    }

    private static boolean looksLikeContractHeaderBefore(byte[] payload, int dateOffset) {
        int off = dateOffset - 16;
        return off >= 0 && off + 16 <= payload.length && isHeaderLike(payload, off);
    }

    private static LocalDate decodeDate(int ordinal, int yearWord) {
        int year = yearWord;
        if (year < 1900 || year > 2100) {
            return null;
        }
        int dayOfYear = ordinal;
        if (dayOfYear < 1 || dayOfYear > 366) {
            return null;
        }
        try {
            return LocalDate.ofYearDay(year, dayOfYear);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static boolean isHeaderLike(byte[] payload, int off) {
        return u16le(payload, off) == 0x076c
                && payload[off + 8] == (byte) 0xff
                && payload[off + 9] == (byte) 0xff
                && payload[off + 10] == (byte) 0xff
                && payload[off + 11] == (byte) 0xff;
    }

    private static int u16le(byte[] payload, int off) {
        return (payload[off] & 0xFF) | ((payload[off + 1] & 0xFF) << 8);
    }

    private static int u32le(byte[] payload, int off) {
        return (payload[off] & 0xFF)
                | ((payload[off + 1] & 0xFF) << 8)
                | ((payload[off + 2] & 0xFF) << 16)
                | ((payload[off + 3] & 0xFF) << 24);
    }

    private static String renderExtraction(Extraction extraction) {
        StringBuilder out = new StringBuilder();
        out.append("{");
        out.append("\"playerId\":").append(Integer.toUnsignedString(extraction.playerId()));
        out.append(",\"pairedHits\":").append(renderInts(extraction.pairedHits()));
        out.append(",\"clusters\":").append(renderCandidates(extraction.candidates()));
        out.append(",\"best\":").append(renderCandidate(extraction.best()));
        out.append("}");
        return out.toString();
    }

    private static String renderCandidates(List<ClusterCandidate> candidates) {
        List<String> rows = new ArrayList<>();
        for (ClusterCandidate candidate : candidates) {
            rows.add(renderCandidate(candidate));
        }
        return "[" + String.join(", ", rows) + "]";
    }

    private static String renderCandidate(ClusterCandidate candidate) {
        if (candidate == null) {
            return "null";
        }
        return "{"
                + "\"anchor\":" + candidate.anchor
                + ",\"familyPriority\":" + candidate.familyPriority
                + ",\"score\":" + candidate.score
                + ",\"headerCount\":" + candidate.headerCount
                + ",\"salary\":" + renderRow(candidate.salary)
                + ",\"contractEnd\":" + renderDateRow(candidate.contractEnd)
                + "}";
    }

    private static String renderRow(Row row) {
        if (row == null) {
            return "null";
        }
        return "{"
                + "\"rel\":" + row.rel
                + ",\"value\":" + row.value
                + ",\"score\":" + row.score
                + ",\"hex\":" + quote(row.hex)
                + "}";
    }

    private static String renderDateRow(DateRow row) {
        if (row == null) {
            return "null";
        }
        return "{"
                + "\"rel\":" + row.rel
                + ",\"score\":" + row.score
                + ",\"ordinal\":" + row.ordinal
                + ",\"year\":" + row.year
                + ",\"date\":" + quote(row.date == null ? "" : row.date.toString())
                + ",\"hex\":" + quote(row.hex)
                + "}";
    }

    private static String renderInts(List<Integer> ints) {
        List<String> values = ints.stream().map(String::valueOf).toList();
        return "[" + String.join(", ", values) + "]";
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String hex(byte[] payload, int offset, int length) {
        int end = Math.min(payload.length, offset + length);
        StringBuilder out = new StringBuilder((end - offset) * 3);
        for (int i = offset; i < end; i++) {
            if (i > offset) {
                out.append(' ');
            }
            out.append(String.format(Locale.ROOT, "%02x", payload[i] & 0xFF));
        }
        return out.toString();
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

    public record Extraction(int playerId, List<Integer> pairedHits, List<ClusterCandidate> candidates, ClusterCandidate best) {
    }

    public record PreparedPayload(
            byte[] payload,
            Map<Integer, List<Integer>> pairedHitsById,
            Map<Integer, ClusterCandidate> clusterCache
    ) {
    }

    public static final class ClusterCandidate {
        private final int anchor;
        private final int familyPriority;
        private final int score;
        private final int headerCount;
        private final Row salary;
        private final DateRow contractEnd;

        private ClusterCandidate(int anchor, int familyPriority, int score, int headerCount, Row salary, DateRow contractEnd) {
            this.anchor = anchor;
            this.familyPriority = familyPriority;
            this.score = score;
            this.headerCount = headerCount;
            this.salary = salary;
            this.contractEnd = contractEnd;
        }

        public int anchor() { return anchor; }
        public int familyPriority() { return familyPriority; }
        public int score() { return score; }
        public int headerCount() { return headerCount; }
        public Row salary() { return salary; }
        public DateRow contractEnd() { return contractEnd; }
    }

    public static final class Row {
        private final int rel;
        private final int value;
        private final int score;
        private final String hex;

        private Row(int rel, int value, int score, String hex) {
            this.rel = rel;
            this.value = value;
            this.score = score;
            this.hex = hex;
        }

        public int rel() { return rel; }
        public int value() { return value; }
        public int score() { return score; }
        public String hex() { return hex; }
    }

    public static final class DateRow {
        private final int rel;
        private final int score;
        private final String hex;
        private final int ordinal;
        private final int year;
        private final LocalDate date;

        private DateRow(int rel, int score, String hex, int ordinal, int year, LocalDate date) {
            this.rel = rel;
            this.score = score;
            this.hex = hex;
            this.ordinal = ordinal;
            this.year = year;
            this.date = date;
        }

        public int rel() { return rel; }
        public int score() { return score; }
        public String hex() { return hex; }
        public int ordinal() { return ordinal; }
        public int year() { return year; }
        public LocalDate date() { return date; }
    }

    private static final class PairSelection {
        private final DateRow date;
        private final Row salary;

        private PairSelection(DateRow date, Row salary) {
            this.date = date;
            this.salary = salary;
        }
    }
}
