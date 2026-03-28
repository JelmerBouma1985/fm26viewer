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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class LinkedContractPatternProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int SEARCH_RADIUS = 1_000;

    private LinkedContractPatternProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));
        Map<String, Integer> anchors = new LinkedHashMap<>();
        anchors.put("pablo_secondary", 69_765_171);
        anchors.put("player_2000259904_linked", 70_602_407);

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        int rendered = 0;
        for (Map.Entry<String, Integer> entry : anchors.entrySet()) {
            out.append("  ").append(quote(entry.getKey())).append(": {\n");
            out.append("    \"anchor\": ").append(entry.getValue()).append(",\n");
            out.append("    \"salaryCandidates\": ").append(renderRows(findSalaryRows(base, entry.getValue()))).append(",\n");
            out.append("    \"dateCandidates\": ").append(renderRows(findDateRows(base, entry.getValue()))).append('\n');
            out.append("  }");
            if (++rendered < anchors.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("}\n");
        System.out.print(out);
    }

    private static List<Row> findSalaryRows(byte[] payload, int anchor) {
        List<Row> rows = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 16; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int value = u32le(payload, off);
            if (value <= 0 || value > 2_000_000) {
                continue;
            }
            if (payload[off + 4] == 0x00 && payload[off + 5] == 0x01 && payload[off + 6] == 0x0b) {
                // skip obviously shifted false positives
                continue;
            }
            if (payload[off + 4] == 0x00) {
                // no-op
            }
            if (payload[off + 4] == 0x01
                    && payload[off + 5] == 0x0b
                    && payload[off + 6] == 0x00
                    && payload[off + 7] == (byte) 0xff
                    && payload[off + 8] == (byte) 0xff
                    && payload[off + 9] == (byte) 0xff
                    && payload[off + 10] == (byte) 0xff) {
                rows.add(new Row(rel, value, hex(payload, off, 16)));
            }
        }
        return rows;
    }

    private static List<Row> findDateRows(byte[] payload, int anchor) {
        List<Row> rows = new ArrayList<>();
        for (int rel = -SEARCH_RADIUS; rel <= SEARCH_RADIUS - 16; rel++) {
            int off = anchor + rel;
            if (off < 0 || off + 16 > payload.length) {
                continue;
            }
            int dayOrOrdinal = u16le(payload, off);
            int year1 = u16le(payload, off + 2);
            int day2 = u16le(payload, off + 4);
            int year2 = u16le(payload, off + 6);
            int marker1 = u16le(payload, off + 8);
            int marker2 = u16le(payload, off + 10);
            if (dayOrOrdinal >= 0x0070 && dayOrOrdinal <= 0x01ff
                    && year1 >= 0x07e0 && year1 <= 0x07f8
                    && day2 >= 0x0070 && day2 <= 0x3000
                    && year2 >= 0x07e0 && year2 <= 0x07f8
                    && marker1 <= 0x0040
                    && marker2 <= 0x5000) {
                rows.add(new Row(rel, year1, hex(payload, off, 16)));
            }
        }
        return rows;
    }

    private static String renderRows(List<Row> rows) {
        List<String> rendered = new ArrayList<>();
        for (Row row : rows) {
            rendered.add("{\"rel\":" + row.rel() + ",\"value\":" + row.value() + ",\"hex\":" + quote(row.hex()) + "}");
        }
        return "[" + String.join(", ", rendered) + "]";
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

    private record Row(int rel, int value, String hex) {
    }
}
