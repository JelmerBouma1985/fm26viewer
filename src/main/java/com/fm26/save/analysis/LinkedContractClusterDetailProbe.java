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

public final class LinkedContractClusterDetailProbe {

    private static final int FMF_ZSTD_OFFSET = 26;

    private LinkedContractClusterDetailProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));
        byte[] salary = loadPayload(Path.of("games/2000259904_salary_50k_to_750k.fm"));
        byte[] contract = loadPayload(Path.of("games/2000259904_contract_end_2031_06_30_to_2035_05_01.fm"));

        dump("salary", base, 70_602_407, salary, 70_606_521);
        dump("contract", base, 70_602_407, contract, 70_607_005);
    }

    private static void dump(String label, byte[] base, int baseHit, byte[] changed, int changedHit) {
        System.out.println("## " + label + " baseHit=" + baseHit + " changedHit=" + changedHit);
        List<Integer> diffs = new ArrayList<>();
        for (int rel = -1000; rel <= 1000; rel++) {
            int bo = baseHit + rel;
            int co = changedHit + rel;
            if (bo < 0 || co < 0 || bo >= base.length || co >= changed.length) {
                continue;
            }
            if (base[bo] != changed[co]) {
                diffs.add(rel);
            }
        }
        System.out.println("diffCount=" + diffs.size());
        System.out.println("diffs=" + diffs);
        for (int rel = -900; rel <= 900; rel += 4) {
            int bo = baseHit + rel;
            int co = changedHit + rel;
            if (bo < 0 || co < 0 || bo + 16 > base.length || co + 16 > changed.length) {
                continue;
            }
            byte[] b = slice(base, bo, 16);
            byte[] c = slice(changed, co, 16);
            if (!different(b, c) && !interesting(b)) {
                continue;
            }
            System.out.println(rel
                    + " base=" + hex(b)
                    + " changed=" + hex(c)
                    + " bu32=" + u32s(b)
                    + " cu32=" + u32s(c));
        }
    }

    private static boolean interesting(byte[] row) {
        return containsWord(row, 0x076c)
                || containsWord(row, 0x07ea)
                || containsWord(row, 0x07ed)
                || containsWord(row, 0x07f3)
                || u32le(row, 0) == 50_000
                || u32le(row, 0) == 750_000
                || u32le(row, 4) == 50_000
                || u32le(row, 4) == 750_000
                || u32le(row, 8) == 50_000
                || u32le(row, 8) == 750_000
                || u32le(row, 12) == 50_000
                || u32le(row, 12) == 750_000;
    }

    private static boolean containsWord(byte[] row, int word) {
        for (int i = 0; i + 1 < row.length; i++) {
            int value = (row[i] & 0xFF) | ((row[i + 1] & 0xFF) << 8);
            if (value == word) {
                return true;
            }
        }
        return false;
    }

    private static boolean different(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return true;
            }
        }
        return false;
    }

    private static byte[] slice(byte[] payload, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(payload, off, out, 0, len);
        return out;
    }

    private static String u32s(byte[] bytes) {
        return "[" + Integer.toUnsignedString(u32le(bytes, 0)) + ","
                + Integer.toUnsignedString(u32le(bytes, 4)) + ","
                + Integer.toUnsignedString(u32le(bytes, 8)) + ","
                + Integer.toUnsignedString(u32le(bytes, 12)) + "]";
    }

    private static String hex(byte[] payload) {
        StringBuilder out = new StringBuilder(payload.length * 3);
        for (int i = 0; i < payload.length; i++) {
            if (i > 0) {
                out.append(' ');
            }
            out.append(String.format(Locale.ROOT, "%02x", payload[i] & 0xFF));
        }
        return out.toString();
    }

    private static int u32le(byte[] payload, int off) {
        return (payload[off] & 0xFF)
                | ((payload[off + 1] & 0xFF) << 8)
                | ((payload[off + 2] & 0xFF) << 16)
                | ((payload[off + 3] & 0xFF) << 24);
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
}
