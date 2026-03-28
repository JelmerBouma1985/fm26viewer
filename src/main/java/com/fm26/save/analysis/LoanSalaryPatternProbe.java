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

public final class LoanSalaryPatternProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int SEARCH_RADIUS = 1000;

    private LoanSalaryPatternProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] payload = loadPayload(Path.of("games/Feyenoord_after.fm"));
        List<Integer> ids = List.of(
                2000190514, 2000144944, 2000146262, 89054469, 2000144336, 51055914,
                37078941, 2000095738, 2000014083, 2000169768, 37084989, 37084608,
                2000216551, 2000215448, 2000133549, 2000336990, 2000241574, 37085048);
        for (int playerId : ids) {
            IsolatedContractExtractor.Extraction extraction = IsolatedContractExtractor.extract(payload, playerId);
            IsolatedContractExtractor.ClusterCandidate best = extraction.best();
            System.out.println("## " + playerId + " anchor=" + (best == null ? -1 : best.anchor()));
            if (best == null) {
                continue;
            }
            int anchor = best.anchor();
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
                    System.out.println("rel=" + rel + " value=" + value + " hex=" + hex(payload, off, 16));
                }
            }
        }
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
}
