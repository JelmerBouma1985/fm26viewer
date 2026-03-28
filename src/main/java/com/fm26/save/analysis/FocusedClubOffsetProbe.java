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

public final class FocusedClubOffsetProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int[] DELTAS = {264, 1440};

    private FocusedClubOffsetProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));

        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("trauner_to_1009", new Scenario(16_023_929, 66_583_225, Path.of("games/trauner_to_1009.fm")));
        scenarios.put("smal_to_1009", new Scenario(37_060_899, 67_755_429, Path.of("games/smal_to_1009.fm")));
        scenarios.put("bos_loaned_out_to_1009", new Scenario(2_000_015_266, 69_655_129, Path.of("games/bos_loaned_out_to_1009.fm")));
        scenarios.put("beelen_loaned_out_to_1009", new Scenario(37_076_406, 67_992_279, Path.of("games/beelen_loaned_out_to_1009.fm")));
        scenarios.put("zechiel_back_to_1013", new Scenario(2_000_054_498, 69_857_442, Path.of("games/zechiel_back_to_1013.fm")));
        scenarios.put("plug_back_to_1013", new Scenario(2_000_122_311, 70_076_006, Path.of("games/plug_back_to_1013.fm")));

        StringBuilder out = new StringBuilder(8192);
        out.append("{\n");
        int rendered = 0;
        for (Map.Entry<String, Scenario> entry : scenarios.entrySet()) {
            byte[] changed = loadPayload(entry.getValue().save());
            out.append("  ").append(quote(entry.getKey())).append(": {\n");
            field(out, 4, "playerId", Integer.toUnsignedString(entry.getValue().playerId()), true);
            field(out, 4, "personPair", Integer.toString(entry.getValue().personPair()), true);
            for (int i = 0; i < DELTAS.length; i++) {
                int delta = DELTAS[i];
                int offset = entry.getValue().personPair() + delta;
                int baseU32 = inRange(base, offset) ? u32le(base, offset) : -1;
                int changedU32 = inRange(changed, offset) ? u32le(changed, offset) : -1;
                field(out, 4, "delta_" + delta,
                        "{\"offset\":" + offset
                                + ",\"baseU32\":" + Integer.toUnsignedString(baseU32)
                                + ",\"changedU32\":" + Integer.toUnsignedString(changedU32)
                                + ",\"baseHex\":" + quote(hex(base, offset, 16))
                                + ",\"changedHex\":" + quote(hex(changed, offset, 16))
                                + "}",
                        i + 1 < DELTAS.length);
            }
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

    private static boolean inRange(byte[] payload, int offset) {
        return offset >= 0 && offset + 4 <= payload.length;
    }

    private static String hex(byte[] payload, int offset, int length) {
        if (offset < 0 || offset + length > payload.length) {
            return "";
        }
        StringBuilder out = new StringBuilder(length * 3);
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                out.append(' ');
            }
            out.append(String.format(Locale.ROOT, "%02x", payload[offset + i] & 0xFF));
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

    private record Scenario(int playerId, int personPair, Path save) {
    }
}
