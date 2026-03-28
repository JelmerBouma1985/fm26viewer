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
import java.util.List;
import java.util.Locale;

public final class PabloContractAnchorProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int PLAYER_ID = 2_000_040_347;
    private static final int BASE_PAIR = 39_981_836;
    private static final int SALARY_PAIR = 39_989_854;
    private static final int CONTRACT_PAIR = 39_990_250;

    private PabloContractAnchorProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));
        byte[] salary = loadPayload(Path.of("games/2000040347_salary_39k_to_750k.fm"));
        byte[] contract = loadPayload(Path.of("games/2000040347_contract_end_2029_06_30_to_2035_05_01.fm"));

        List<Integer> baseHits = findHits(base);
        List<Integer> salaryHits = findHits(salary);
        List<Integer> contractHits = findHits(contract);
        System.out.println("baseHits=" + baseHits);
        System.out.println("salaryHits=" + salaryHits);
        System.out.println("contractHits=" + contractHits);
        dumpBand("salary", base, BASE_PAIR, salary, SALARY_PAIR);
        dumpBand("contract", base, BASE_PAIR, contract, CONTRACT_PAIR);
        compareClusters("salary", base, baseHits, salary, salaryHits);
        compareClusters("contract", base, baseHits, contract, contractHits);
        dumpSecondCluster("salary-second", base, 69_765_171, salary, 69_769_709);
        dumpSecondCluster("contract-second", base, 69_765_171, contract, 69_770_193);
    }

    private static List<Integer> findHits(byte[] payload) {
        byte[] pattern = u32(PLAYER_ID);
        List<Integer> hits = new ArrayList<>();
        int start = 0;
        while (true) {
            int hit = indexOf(payload, pattern, start);
            if (hit < 0) {
                break;
            }
            boolean paired = hit + 8 <= payload.length && u32le(payload, hit + 4) == PLAYER_ID;
            if (paired) {
                hits.add(hit);
            }
            start = hit + 1;
        }
        return hits;
    }

    private static void compareClusters(String label, byte[] base, List<Integer> baseHits, byte[] changed, List<Integer> changedHits) {
        System.out.println("## clusterDiff " + label);
        for (int baseHit : baseHits) {
            int changedHit = changedHits.stream()
                    .min(Comparator.comparingInt(hit -> Math.abs(hit - baseHit)))
                    .orElseThrow();
            for (int radius : new int[]{1000, 4000, 12000}) {
                int diffCount = 0;
                for (int rel = -radius; rel <= radius; rel++) {
                    int bo = baseHit + rel;
                    int co = changedHit + rel;
                    if (bo < 0 || co < 0 || bo >= base.length || co >= changed.length) {
                        continue;
                    }
                    if (base[bo] != changed[co]) {
                        diffCount++;
                    }
                }
                System.out.println("baseHit=" + baseHit + " changedHit=" + changedHit + " radius=" + radius + " diffCount=" + diffCount);
            }
        }
    }

    private static void dumpBand(String label, byte[] base, int basePair, byte[] changed, int changedPair) {
        System.out.println("## " + label + " basePair=" + basePair + " changedPair=" + changedPair);
        List<Integer> diffs = new ArrayList<>();
        for (int rel = -1000; rel <= 1000; rel++) {
            int bo = basePair + rel;
            int co = changedPair + rel;
            if (bo < 0 || co < 0 || bo >= base.length || co >= changed.length) {
                continue;
            }
            if (base[bo] != changed[co]) {
                diffs.add(rel);
            }
        }
        System.out.println("diffCount=" + diffs.size());
        System.out.println("diffsSample=" + diffs.stream().limit(120).toList());
        for (int rel = -800; rel <= 800; rel += 4) {
            int bo = basePair + rel;
            int co = changedPair + rel;
            if (bo < 0 || co < 0 || bo + 16 > base.length || co + 16 > changed.length) {
                continue;
            }
            byte[] b = slice(base, bo, 16);
            byte[] c = slice(changed, co, 16);
            if (!interesting(b, c)) {
                continue;
            }
            System.out.println(rel
                    + " base=" + hex(b)
                    + " changed=" + hex(c)
                    + " bu32=" + u32s(b)
                    + " cu32=" + u32s(c));
        }
    }

    private static void dumpSecondCluster(String label, byte[] base, int basePair, byte[] changed, int changedPair) {
        System.out.println("## " + label + " basePair=" + basePair + " changedPair=" + changedPair);
        List<Integer> diffs = new ArrayList<>();
        for (int rel = -1200; rel <= 1200; rel++) {
            int bo = basePair + rel;
            int co = changedPair + rel;
            if (bo < 0 || co < 0 || bo >= base.length || co >= changed.length) {
                continue;
            }
            if (base[bo] != changed[co]) {
                diffs.add(rel);
            }
        }
        System.out.println("secondDiffCount=" + diffs.size());
        System.out.println("secondDiffsSample=" + diffs.stream().limit(160).toList());
        for (int rel = -900; rel <= 900; rel += 4) {
            int bo = basePair + rel;
            int co = changedPair + rel;
            if (bo < 0 || co < 0 || bo + 16 > base.length || co + 16 > changed.length) {
                continue;
            }
            byte[] b = slice(base, bo, 16);
            byte[] c = slice(changed, co, 16);
            if (!different(b, c)) {
                continue;
            }
            System.out.println(rel
                    + " base=" + hex(b)
                    + " changed=" + hex(c)
                    + " bu32=" + u32s(b)
                    + " cu32=" + u32s(c));
        }
    }

    private static boolean interesting(byte[] base, byte[] changed) {
        if (!different(base, changed)) {
            return false;
        }
        int[] vals = {
                u32le(base, 0), u32le(base, 4), u32le(base, 8), u32le(base, 12),
                u32le(changed, 0), u32le(changed, 4), u32le(changed, 8), u32le(changed, 12)
        };
        for (int value : vals) {
            if (value == 39_000 || value == 750_000 || value == 1009 || value == 1013) {
                return true;
            }
        }
        return containsWord(base, 0x076c) || containsWord(changed, 0x076c);
    }

    private static boolean different(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsWord(byte[] bytes, int word) {
        for (int i = 0; i + 1 < bytes.length; i++) {
            int value = (bytes[i] & 0xFF) | ((bytes[i + 1] & 0xFF) << 8);
            if (value == word) {
                return true;
            }
        }
        return false;
    }

    private static byte[] slice(byte[] payload, int offset, int length) {
        byte[] out = new byte[length];
        System.arraycopy(payload, offset, out, 0, length);
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

    private static int indexOf(byte[] payload, byte[] needle, int start) {
        outer:
        for (int off = Math.max(0, start); off + needle.length <= payload.length; off++) {
            for (int i = 0; i < needle.length; i++) {
                if (payload[off + i] != needle[i]) {
                    continue outer;
                }
            }
            return off;
        }
        return -1;
    }

    private static byte[] u32(int value) {
        return new byte[]{
                (byte) (value & 0xFF),
                (byte) ((value >>> 8) & 0xFF),
                (byte) ((value >>> 16) & 0xFF),
                (byte) ((value >>> 24) & 0xFF)
        };
    }

    private static int u32le(byte[] payload, int offset) {
        return (payload[offset] & 0xFF)
                | ((payload[offset + 1] & 0xFF) << 8)
                | ((payload[offset + 2] & 0xFF) << 16)
                | ((payload[offset + 3] & 0xFF) << 24);
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
