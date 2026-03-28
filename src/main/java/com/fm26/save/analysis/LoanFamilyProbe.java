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
import java.util.List;
import java.util.Locale;

public final class LoanFamilyProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int SEARCH_RADIUS = 1000;

    private LoanFamilyProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path csv = Path.of("loan.csv");
        byte[] payload = loadPayload(Path.of("games/Feyenoord_after.fm"));
        List<Row> rows = readCsv(csv);
        for (Row row : rows) {
            IsolatedContractExtractor.Extraction extraction = IsolatedContractExtractor.extract(payload, row.id());
            IsolatedContractExtractor.ClusterCandidate best = extraction.best();
            System.out.println("## " + row.id() + " " + row.name());
            System.out.println("expected loan=" + row.loanExpiryDate() + " parent=" + row.parentContractEndDate() + " salary=" + row.salaryPerWeek());
            if (best == null) {
                System.out.println("NO_BEST_CLUSTER");
                continue;
            }
            int anchor = best.anchor();
            System.out.println("anchor=" + anchor);
            List<DateCandidate> dates = findDates(payload, anchor);
            List<SalaryCandidate> salaries = findSalaryPatternRows(payload, anchor);
            List<SalaryCandidate> exacts = findExactSalaryHits(payload, anchor, row.salaryPerWeek());
            System.out.println("dateCandidates=" + renderDates(dates));
            System.out.println("salaryPatternCandidates=" + renderSalaries(salaries));
            System.out.println("exactSalaryHits=" + renderSalaries(exacts));
        }
    }

    private static List<DateCandidate> findDates(byte[] payload, int anchor) {
        List<DateCandidate> out = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 16; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int ordinal1 = u16le(payload, off);
            int year1 = u16le(payload, off + 2);
            int ordinal2 = u16le(payload, off + 4);
            int year2 = u16le(payload, off + 6);
            if (ordinal1 >= 120 && ordinal1 <= 370
                    && year1 >= 2025 && year1 <= 2035
                    && ordinal2 >= 120 && ordinal2 <= 10000
                    && year2 >= 2025 && year2 <= 2035) {
                LocalDate date = decodeDate(ordinal1, year1);
                out.add(new DateCandidate(rel, ordinal1, year1, ordinal2, year2, date, hex(payload, off, 16)));
            }
        }
        out.sort(Comparator.comparingInt(DateCandidate::rel));
        return out;
    }

    private static List<SalaryCandidate> findSalaryPatternRows(byte[] payload, int anchor) {
        List<SalaryCandidate> out = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 16; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int value = u32le(payload, off);
            if (value > 0 && value <= 250_000
                    && payload[off + 4] == 0x01
                    && payload[off + 5] == 0x0b
                    && payload[off + 6] == 0x00
                    && payload[off + 7] == (byte) 0xff
                    && payload[off + 8] == (byte) 0xff
                    && payload[off + 9] == (byte) 0xff
                    && payload[off + 10] == (byte) 0xff) {
                out.add(new SalaryCandidate(rel, value, hex(payload, off, 16)));
            }
        }
        out.sort(Comparator.comparingInt(SalaryCandidate::rel));
        return out;
    }

    private static List<SalaryCandidate> findExactSalaryHits(byte[] payload, int anchor, int expected) {
        List<SalaryCandidate> out = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 4; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 4 > payload.length) {
                continue;
            }
            int value = u32le(payload, off);
            if (value == expected) {
                out.add(new SalaryCandidate(rel, value, hex(payload, off, 16)));
            }
        }
        out.sort(Comparator.comparingInt(SalaryCandidate::rel));
        return out;
    }

    private static LocalDate decodeDate(int ordinal, int year) {
        if (ordinal < 1 || ordinal > 366) {
            return null;
        }
        try {
            return LocalDate.ofYearDay(year, ordinal);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static String renderDates(List<DateCandidate> dates) {
        List<String> items = new ArrayList<>();
        for (DateCandidate d : dates) {
            items.add("{rel=" + d.rel + ",date=" + d.date + ",year2=" + d.year2 + ",ord2=" + d.ordinal2 + ",hex='" + d.hex + "'}");
        }
        return items.toString();
    }

    private static String renderSalaries(List<SalaryCandidate> salaries) {
        List<String> items = new ArrayList<>();
        for (SalaryCandidate s : salaries) {
            items.add("{rel=" + s.rel + ",value=" + s.value + ",hex='" + s.hex + "'}");
        }
        return items.toString();
    }

    private static List<Row> readCsv(Path csv) throws IOException {
        List<Row> rows = new ArrayList<>();
        List<String> lines = Files.readAllLines(csv);
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split(",", 5);
            rows.add(new Row(
                    Integer.parseUnsignedInt(parts[0]),
                    parts[1],
                    LocalDate.parse(parts[2]),
                    LocalDate.parse(parts[3]),
                    Integer.parseInt(parts[4])));
        }
        return rows;
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

    private record Row(int id, String name, LocalDate loanExpiryDate, LocalDate parentContractEndDate, int salaryPerWeek) {
    }

    private record DateCandidate(int rel, int ordinal1, int year1, int ordinal2, int year2, LocalDate date, String hex) {
    }

    private record SalaryCandidate(int rel, int value, String hex) {
    }
}
