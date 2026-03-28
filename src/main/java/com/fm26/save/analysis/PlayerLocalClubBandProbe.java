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
import java.util.Set;

public final class PlayerLocalClubBandProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int BAND_START = -1100;
    private static final int BAND_END = -900;
    private static final Set<Integer> KNOWN_CLUB_IDS = Set.of(156, 982, 1001, 1004, 1009, 1010, 1013, 1014, 1015, 1455, 2215);

    private PlayerLocalClubBandProbe() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("trauner_base", new Scenario(16_023_929, 66_583_225, Path.of("/tmp/fey_base.bin"), "base"));
        scenarios.put("trauner_to_1009", new Scenario(16_023_929, 66_591_480, Path.of("/tmp/trauner_1009.bin"), "to_1009"));
        scenarios.put("smal_base", new Scenario(37_060_899, 67_755_429, Path.of("/tmp/fey_base.bin"), "base"));
        scenarios.put("smal_to_1009", new Scenario(37_060_899, 67_762_684, Path.of("/tmp/smal_1009.bin"), "to_1009"));
        scenarios.put("bos_base", new Scenario(2_000_015_266, 69_655_129, Path.of("/tmp/fey_base.bin"), "base"));
        scenarios.put("bos_loaned_out_to_1009", new Scenario(2_000_015_266, 69_660_694, Path.of("/tmp/bos_1009.bin"), "loaned_out_to_1009"));
        scenarios.put("beelen_base", new Scenario(37_076_406, 67_992_279, Path.of("/tmp/fey_base.bin"), "base"));
        scenarios.put("beelen_loaned_out_to_1009", new Scenario(37_076_406, 67_999_409, Path.of("/tmp/beelen_1009.bin"), "loaned_out_to_1009"));
        scenarios.put("plug_base", new Scenario(2_000_122_311, 70_076_006, Path.of("/tmp/fey_base.bin"), "base"));
        scenarios.put("plug_back_to_1013", new Scenario(2_000_122_311, 70_081_303, Path.of("/tmp/plug_1013.bin"), "back_to_1013"));
        scenarios.put("zechiel_base", new Scenario(2_000_054_498, 69_857_442, Path.of("/tmp/fey_base.bin"), "base"));
        scenarios.put("zechiel_back_to_1013", new Scenario(2_000_054_498, 69_862_677, Path.of("/tmp/zechiel_1013.bin"), "back_to_1013"));

        StringBuilder out = new StringBuilder(32768);
        out.append("{\n");
        int rendered = 0;
        for (Map.Entry<String, Scenario> entry : scenarios.entrySet()) {
            byte[] payload = loadPayload(entry.getValue().payload());
            out.append("  ").append(quote(entry.getKey())).append(": {\n");
            field(out, 4, "playerId", Integer.toUnsignedString(entry.getValue().playerId()), true);
            field(out, 4, "personPair", Integer.toString(entry.getValue().personPair()), true);
            field(out, 4, "variant", quote(entry.getValue().variant()), true);
            field(out, 4, "hits", renderHits(payload, entry.getValue().personPair()), false);
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

    private static String renderHits(byte[] payload, int personPair) {
        List<String> hits = new ArrayList<>();
        for (int delta = BAND_START; delta <= BAND_END; delta++) {
            int offset = personPair + delta;
            if (offset < 0 || offset + 4 > payload.length) {
                continue;
            }
            int value = u32le(payload, offset);
            if (!KNOWN_CLUB_IDS.contains(value)) {
                continue;
            }
            hits.add("{\"delta\":" + delta
                    + ",\"offset\":" + offset
                    + ",\"clubId\":" + value
                    + ",\"hex\":" + quote(hex(payload, offset, 16))
                    + "}");
        }
        return "[" + String.join(", ", hits) + "]";
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

    private record Scenario(int playerId, int personPair, Path payload, String variant) {
    }
}
