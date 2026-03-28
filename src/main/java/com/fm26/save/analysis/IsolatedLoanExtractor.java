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

public final class IsolatedLoanExtractor {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int SEARCH_RADIUS = 1000;

    private IsolatedLoanExtractor() {
    }

    public static LoanExtraction extract(byte[] payload, int playerId) {
        return extract(IsolatedContractExtractor.prepare(payload), playerId);
    }

    public static LoanExtraction extract(IsolatedContractExtractor.PreparedPayload prepared, int playerId) {
        IsolatedContractExtractor.Extraction base = IsolatedContractExtractor.extract(prepared, playerId);
        IsolatedContractExtractor.ClusterCandidate best = base.best();
        if (best == null) {
            return new LoanExtraction(playerId, -1, null, null, null);
        }
        byte[] payload = prepared.payload();
        int anchor = best.anchor();
        List<DateCandidate> negativeDates = findNegativeDates(payload, anchor);
        DateCandidate loanExpiry = negativeDates.isEmpty() ? null : negativeDates.getLast();
        DateCandidate parentExpiry = negativeDates.size() >= 2 ? negativeDates.getFirst() : loanExpiry;
        SalaryCandidate salary = findLoanSalary(payload, anchor);
        return new LoanExtraction(playerId, anchor, loanExpiry, parentExpiry, salary);
    }

    private static List<DateCandidate> findNegativeDates(byte[] payload, int anchor) {
        List<DateCandidate> out = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel < 0; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int ordinal1 = u16le(payload, off);
            int year1 = u16le(payload, off + 2);
            if (ordinal1 >= 120 && ordinal1 <= 370
                    && year1 >= 2026 && year1 <= 2035) {
                LocalDate date = decodeDate(ordinal1, year1);
                if (date != null) {
                    out.add(new DateCandidate(rel, date, hex(payload, off, 16)));
                }
            }
        }
        out.sort(Comparator.comparingInt(DateCandidate::rel));
        // Deduplicate exact duplicate dates at different nearby rows by keeping the earliest rel.
        List<DateCandidate> dedup = new ArrayList<>();
        for (DateCandidate candidate : out) {
            boolean seen = dedup.stream().anyMatch(existing -> existing.date.equals(candidate.date));
            if (!seen) {
                dedup.add(candidate);
            }
        }
        return dedup;
    }

    private static SalaryCandidate findLoanSalary(byte[] payload, int anchor) {
        List<SalaryCandidate> exactPattern = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel < 0; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int value = u32le(payload, off);
            if (value <= 0 || value > 250_000) {
                continue;
            }
            if (payload[off + 4] == 0x01
                    && payload[off + 5] == 0x0b
                    && payload[off + 6] == 0x00
                    && payload[off + 7] == 0x01
                    && payload[off + 8] == 0x00
                    && payload[off + 9] == 0x00
                    && payload[off + 10] == 0x00
                    && payload[off + 11] == 0x05) {
                exactPattern.add(new SalaryCandidate(rel, value, hex(payload, off, 16)));
            }
        }
        if (!exactPattern.isEmpty()) {
            return exactPattern.stream()
                    .min(Comparator.comparingInt(candidate -> Math.abs(candidate.rel + 450)))
                    .orElse(null);
        }

        List<SalaryCandidate> looserPattern = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel < 0; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int value = u32le(payload, off);
            if (value <= 0 || value > 250_000) {
                continue;
            }
            if (payload[off + 4] == 0x01
                    && payload[off + 5] == 0x0b
                    && payload[off + 6] == 0x00
                    && payload[off + 7] == 0x01) {
                looserPattern.add(new SalaryCandidate(rel, value, hex(payload, off, 16)));
            }
        }
        return looserPattern.stream()
                .min(Comparator.comparingInt(candidate -> Math.abs(candidate.rel + 450)))
                .orElse(null);
    }

    private static LocalDate decodeDate(int ordinal, int year) {
        try {
            return LocalDate.ofYearDay(year, ordinal);
        } catch (RuntimeException ex) {
            return null;
        }
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

    public static byte[] loadPayload(Path path) throws IOException {
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

    public record LoanExtraction(int playerId, int anchor, DateCandidate loanExpiry, DateCandidate parentExpiry, SalaryCandidate salary) {
    }

    public record DateCandidate(int rel, LocalDate date, String hex) {
    }

    public record SalaryCandidate(int rel, int value, String hex) {
    }
}
