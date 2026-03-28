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
import java.util.List;
import java.util.Locale;

public final class SalaryClusterDebugProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int SEARCH_RADIUS = 1000;

    private SalaryClusterDebugProbe() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            throw new IllegalArgumentException("Usage: SalaryClusterDebugProbe <playerId> [playerId...]");
        }
        byte[] payload = loadPayload(Path.of("games/Feyenoord_after.fm"));
        for (String arg : args) {
            int playerId = Integer.parseUnsignedInt(arg);
            System.out.println("## playerId=" + Integer.toUnsignedString(playerId));
            IsolatedContractExtractor.Extraction extraction = IsolatedContractExtractor.extract(payload, playerId);
            System.out.println("pairedHits=" + extraction.pairedHits());
            System.out.println("best=" + renderBest(extraction.best()));
            for (int hit : extraction.pairedHits()) {
                System.out.println("-- anchor=" + hit);
                dumpCandidates(payload, hit);
            }
        }
    }

    private static void dumpCandidates(byte[] payload, int anchor) {
        List<String> salaryRows = new ArrayList<>();
        List<String> dateRows = new ArrayList<>();
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
                salaryRows.add("salary rel=" + rel + " value=" + value + " hex=" + hex(payload, off, 16));
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
                dateRows.add("date rel=" + rel + " year=" + year1 + " ord=" + ordinal1 + " hex=" + hex(payload, off, 16));
            }
        }
        salaryRows.stream().limit(40).forEach(System.out::println);
        dateRows.stream().limit(40).forEach(System.out::println);
    }

    private static String renderBest(IsolatedContractExtractor.ClusterCandidate candidate) {
        if (candidate == null) return "null";
        return "anchor=" + candidate.anchor()
                + " salary=" + (candidate.salary() == null ? "null" : (candidate.salary().value() + "@" + candidate.salary().rel()))
                + " contractEnd=" + (candidate.contractEnd() == null ? "null" : (candidate.contractEnd().date() + "@" + candidate.contractEnd().rel()));
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
            if (i > offset) out.append(' ');
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
                    if (read < 0) break;
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
}
