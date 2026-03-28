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
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class LinkedContractClusterProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int SEARCH_RADIUS = 1_200;
    private static final int DIFF_RADIUS = 1_200;

    private LinkedContractClusterProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));

        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("pablo", new Scenario(
                2_000_040_347,
                Path.of("games/2000040347_salary_39k_to_750k.fm"),
                Path.of("games/2000040347_contract_end_2029_06_30_to_2035_05_01.fm")));
        scenarios.put("player_2000259904", new Scenario(
                2_000_259_904,
                Path.of("games/2000259904_salary_50k_to_750k.fm"),
                Path.of("games/2000259904_contract_end_2031_06_30_to_2035_05_01.fm")));

        StringBuilder out = new StringBuilder(32768);
        out.append("{\n");
        int rendered = 0;
        for (Map.Entry<String, Scenario> entry : scenarios.entrySet()) {
            byte[] salary = loadPayload(entry.getValue().salarySave());
            byte[] contract = loadPayload(entry.getValue().contractSave());
            List<Integer> baseHits = findPairedHits(base, entry.getValue().playerId());
            List<Integer> salaryHits = findPairedHits(salary, entry.getValue().playerId());
            List<Integer> contractHits = findPairedHits(contract, entry.getValue().playerId());

            out.append("  ").append(quote(entry.getKey())).append(": {\n");
            field(out, 4, "playerId", Integer.toUnsignedString(entry.getValue().playerId()), true);
            field(out, 4, "baseHits", renderIntList(baseHits), true);
            field(out, 4, "clusters", renderClusters(base, baseHits, salary, salaryHits, contract, contractHits), false);
            out.append("  }");
            if (++rendered < scenarios.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("}\n");
        System.out.print(out);
    }

    private static String renderClusters(byte[] base, List<Integer> baseHits, byte[] salary, List<Integer> salaryHits,
                                         byte[] contract, List<Integer> contractHits) {
        List<String> rows = new ArrayList<>();
        for (int baseHit : baseHits) {
            int salaryHit = nearest(salaryHits, baseHit);
            int contractHit = nearest(contractHits, baseHit);
            ContractSignature baseSig = scanSignature(base, baseHit);
            ContractSignature salarySig = scanSignature(salary, salaryHit);
            ContractSignature contractSig = scanSignature(contract, contractHit);
            int salaryDiffs = diffCount(base, baseHit, salary, salaryHit, DIFF_RADIUS);
            int contractDiffs = diffCount(base, baseHit, contract, contractHit, DIFF_RADIUS);
            rows.add("{"
                    + "\"baseHit\":" + baseHit
                    + ",\"salaryHit\":" + salaryHit
                    + ",\"contractHit\":" + contractHit
                    + ",\"salaryDiffs\":" + salaryDiffs
                    + ",\"contractDiffs\":" + contractDiffs
                    + ",\"baseSignature\":" + renderSignature(baseSig)
                    + ",\"salarySignature\":" + renderSignature(salarySig)
                    + ",\"contractSignature\":" + renderSignature(contractSig)
                    + "}");
        }
        return "[" + String.join(", ", rows) + "]";
    }

    private static String renderSignature(ContractSignature sig) {
        if (sig == null) {
            return "null";
        }
        return "{"
                + "\"headerRel\":" + sig.headerRel()
                + ",\"dateRel\":" + sig.dateRel()
                + ",\"salaryRel\":" + sig.salaryRel()
                + ",\"score\":" + sig.score()
                + ",\"headerHex\":" + quote(sig.headerHex())
                + ",\"dateHex\":" + quote(sig.dateHex())
                + ",\"salaryHex\":" + quote(sig.salaryHex())
                + "}";
    }

    private static ContractSignature scanSignature(byte[] payload, int pair) {
        ContractSignature best = null;
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 16; rel++) {
            int off = pair + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            if (!isHeaderRow(payload, off)) {
                continue;
            }
            int dateRel = findDateRow(payload, pair, rel);
            int salaryRel = findSalaryRow(payload, pair, rel);
            int score = 10;
            if (dateRel != Integer.MIN_VALUE) {
                score += 8;
            }
            if (salaryRel != Integer.MIN_VALUE) {
                score += 6;
            }
            ContractSignature candidate = new ContractSignature(
                    rel,
                    dateRel,
                    salaryRel,
                    score,
                    hex(payload, off, 16),
                    dateRel == Integer.MIN_VALUE ? "" : hex(payload, pair + dateRel, 16),
                    salaryRel == Integer.MIN_VALUE ? "" : hex(payload, pair + salaryRel, 16));
            if (best == null || candidate.score() > best.score()
                    || (candidate.score() == best.score() && Math.abs(candidate.headerRel()) < Math.abs(best.headerRel()))) {
                best = candidate;
            }
        }
        return best;
    }

    private static boolean isHeaderRow(byte[] payload, int off) {
        return u16le(payload, off) == 0x076c
                && payload[off + 4] == 0x00
                && payload[off + 5] == 0x00
                && payload[off + 8] == (byte) 0xff
                && payload[off + 9] == (byte) 0xff
                && payload[off + 10] == (byte) 0xff
                && payload[off + 11] == (byte) 0xff;
    }

    private static int findDateRow(byte[] payload, int pair, int headerRel) {
        for (int rel = headerRel - 64; rel <= headerRel + 64; rel += 2) {
            int off = pair + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int yearWord = u16le(payload, off + 2);
            if ((payload[off] == (byte) 0xb5 || payload[off] == (byte) 0xb6 || payload[off] == 0x79)
                    && yearWord >= 0x07e0 && yearWord <= 0x07f8) {
                return rel;
            }
        }
        return Integer.MIN_VALUE;
    }

    private static int findSalaryRow(byte[] payload, int pair, int headerRel) {
        for (int rel = headerRel - 320; rel <= headerRel + 320; rel += 4) {
            int off = pair + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            if (payload[off + 4] == 0x01
                    && payload[off + 5] == 0x0b
                    && payload[off + 6] == 0x00
                    && payload[off + 7] == (byte) 0xff
                    && payload[off + 8] == (byte) 0xff
                    && payload[off + 9] == (byte) 0xff
                    && payload[off + 10] == (byte) 0xff) {
                return rel;
            }
            if (payload[off + 12] == 0x05 || payload[off + 12] == 0x0a) {
                int tail = u16le(payload, off + 14);
                if (tail == 0x805a) {
                    return rel + 12;
                }
            }
        }
        return Integer.MIN_VALUE;
    }

    private static int diffCount(byte[] base, int baseHit, byte[] changed, int changedHit, int radius) {
        int diffs = 0;
        for (int rel = -radius; rel <= radius; rel++) {
            int bo = baseHit + rel;
            int co = changedHit + rel;
            if (bo < 0 || co < 0 || bo >= base.length || co >= changed.length) {
                continue;
            }
            if (base[bo] != changed[co]) {
                diffs++;
            }
        }
        return diffs;
    }

    private static List<Integer> findPairedHits(byte[] payload, int playerId) {
        byte[] needle = u32(playerId);
        List<Integer> hits = new ArrayList<>();
        int start = 0;
        while (true) {
            int hit = indexOf(payload, needle, start);
            if (hit < 0) {
                break;
            }
            if (hit + 8 <= payload.length && u32le(payload, hit + 4) == playerId) {
                hits.add(hit);
            }
            start = hit + 1;
        }
        return hits;
    }

    private static int nearest(List<Integer> hits, int target) {
        return hits.stream()
                .min(Comparator.comparingInt(hit -> Math.abs(hit - target)))
                .orElseThrow();
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

    private static int u16le(byte[] payload, int off) {
        return (payload[off] & 0xFF) | ((payload[off + 1] & 0xFF) << 8);
    }

    private static int u32le(byte[] payload, int off) {
        return (payload[off] & 0xFF)
                | ((payload[off + 1] & 0xFF) << 8)
                | ((payload[off + 2] & 0xFF) << 16)
                | ((payload[off + 3] & 0xFF) << 24);
    }

    private static byte[] u32(int value) {
        return new byte[]{
                (byte) (value & 0xFF),
                (byte) ((value >>> 8) & 0xFF),
                (byte) ((value >>> 16) & 0xFF),
                (byte) ((value >>> 24) & 0xFF)
        };
    }

    private static String renderIntList(List<Integer> values) {
        List<String> items = values.stream().map(String::valueOf).toList();
        return "[" + String.join(", ", items) + "]";
    }

    private static void field(StringBuilder out, int indent, String key, String value, boolean comma) {
        out.append(" ".repeat(indent)).append(quote(key)).append(": ").append(value);
        if (comma) {
            out.append(',');
        }
        out.append('\n');
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

    private record Scenario(int playerId, Path salarySave, Path contractSave) {
    }

    private record ContractSignature(int headerRel, int dateRel, int salaryRel, int score,
                                     String headerHex, String dateHex, String salaryHex) {
    }
}
