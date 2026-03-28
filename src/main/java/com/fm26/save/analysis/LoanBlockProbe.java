package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class LoanBlockProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_START = -1120;
    private static final int WINDOW_END = -860;

    private LoanBlockProbe() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("trauner_permanent", new Scenario(Path.of("/tmp/trauner_permanent_1009.bin"), 66_590_781));
        scenarios.put("trauner_loan", new Scenario(Path.of("/tmp/trauner_loan_1009.bin"), 66_590_782));
        scenarios.put("smal_permanent", new Scenario(Path.of("/tmp/smal_permanent_1009.bin"), 67_761_985));
        scenarios.put("smal_loan", new Scenario(Path.of("/tmp/smal_loan_1009.bin"), 67_761_950));
        scenarios.put("bos_base", new Scenario(Path.of("/tmp/fey_base.bin"), 69_655_129));
        scenarios.put("bos_changed", new Scenario(Path.of("/tmp/bos_1009.bin"), 69_660_694));
        scenarios.put("beelen_base", new Scenario(Path.of("/tmp/fey_base.bin"), 67_992_279));
        scenarios.put("beelen_changed", new Scenario(Path.of("/tmp/beelen_1009.bin"), 67_999_409));
        scenarios.put("plug_base", new Scenario(Path.of("/tmp/fey_base.bin"), 70_076_006));
        scenarios.put("plug_changed", new Scenario(Path.of("/tmp/plug_1013.bin"), 70_081_303));
        scenarios.put("zechiel_base", new Scenario(Path.of("/tmp/fey_base.bin"), 69_857_442));
        scenarios.put("zechiel_changed", new Scenario(Path.of("/tmp/zechiel_1013.bin"), 69_862_677));

        StringBuilder out = new StringBuilder(65536);
        out.append("{\n");
        int rendered = 0;
        for (Map.Entry<String, Scenario> entry : scenarios.entrySet()) {
            byte[] payload = loadPayload(entry.getValue().payload());
            out.append("  ").append(quote(entry.getKey())).append(": {\n");
            field(out, 4, "personPair", Integer.toString(entry.getValue().personPair()), true);
            field(out, 4, "windowHex", quote(hex(payload, entry.getValue().personPair() + WINDOW_START, WINDOW_END - WINDOW_START)), true);
            field(out, 4, "markers", renderMarkers(payload, entry.getValue().personPair()), false);
            out.append("  }");
            rendered++;
            if (rendered < scenarios.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        out.append("}\n");
        System.out.print(out);
    }

    private static String renderMarkers(byte[] payload, int personPair) {
        int[] rels = {-1008, -1007, -1000, -972, -968, -967, -966, -964, -960, -928, -927, -926, -925, -924, -923, -922};
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (int rel : rels) {
            int offset = personPair + rel;
            if (offset < 0 || offset + 8 > payload.length) {
                continue;
            }
            if (!first) {
                out.append(", ");
            }
            first = false;
            out.append("{\"rel\":").append(rel)
                    .append(",\"offset\":").append(offset)
                    .append(",\"u32\":").append(Integer.toUnsignedString(u32le(payload, offset)))
                    .append(",\"hex\":").append(quote(hex(payload, offset, 8)))
                    .append("}");
        }
        out.append("]");
        return out.toString();
    }

    private static String hex(byte[] payload, int offset, int length) {
        if (offset < 0 || offset >= payload.length) {
            return "";
        }
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

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record Scenario(Path payload, int personPair) {
    }
}
