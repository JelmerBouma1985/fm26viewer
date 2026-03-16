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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

public final class SmalCandidateOffsetProbe {

    private static final int FMF_ZSTD_OFFSET = 26;

    private SmalCandidateOffsetProbe() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, Path> saves = new LinkedHashMap<>();
        saves.put("base", Path.of("games/Feyenoord_after.fm"));
        saves.put("finishing", Path.of("games/Small_finishing_only.fm"));
        saves.put("pace", Path.of("games/Small_pace_only.fm"));
        saves.put("concentration", Path.of("games/Small_concentration_only.fm"));
        saves.put("controversy", Path.of("games/Small_controversy_only.fm"));
        saves.put("potential_ability", Path.of("games/Small_potential_ability_only.fm"));
        saves.put("striker", Path.of("games/Small_striker_only.fm"));
        saves.put("contract_end", Path.of("games/Small_contract_end_only.fm"));
        saves.put("date_of_birth", Path.of("games/Small_date_of_birth_only.fm"));

        Map<String, byte[]> payloads = new LinkedHashMap<>();
        for (Map.Entry<String, Path> entry : saves.entrySet()) {
            payloads.put(entry.getKey(), loadPayload(entry.getValue()));
        }

        List<Integer> offsets = List.of(
                67_760_594, 67_760_628, 67_760_633, 67_760_669, 67_760_684, 67_761_416,
                67_761_236, 67_761_238, 67_761_388, 67_761_390,
                72_751_381, 72_751_382, 72_751_383,
                73_077_651, 73_077_894, 73_153_853, 73_154_282,
                64_953_962, 64_953_963, 64_953_964,
                64_957_234, 64_957_235, 64_957_236,
                64_980_397, 64_980_398, 64_980_399
        );

        StringBuilder json = new StringBuilder(24_000);
        json.append("{\n  \"offsets\": [\n");
        for (int i = 0; i < offsets.size(); i++) {
            int offset = offsets.get(i);
            Map<String, Integer> values = new LinkedHashMap<>();
            TreeSet<Integer> unique = new TreeSet<>();
            for (Map.Entry<String, byte[]> entry : payloads.entrySet()) {
                int value = entry.getValue()[offset] & 0xFF;
                values.put(entry.getKey(), value);
                unique.add(value);
            }
            if (unique.size() <= 1) {
                continue;
            }
            json.append("    {\n");
            field(json, "offset", Integer.toString(offset), false, true);
            field(json, "uniqueValues", intList(unique), false, true);
            json.append("      \"values\": {\n");
            int rendered = 0;
            for (Map.Entry<String, Integer> entry : values.entrySet()) {
                field(json, entry.getKey(), Integer.toString(entry.getValue()), false, rendered + 1 < values.size(), 8);
                rendered++;
            }
            json.append("      }\n");
            json.append("    }");
            if (i + 1 < offsets.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n}\n");
        System.out.print(json);
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

    private static String intList(TreeSet<Integer> values) {
        StringBuilder out = new StringBuilder("[");
        int i = 0;
        for (Integer value : values) {
            if (i++ > 0) {
                out.append(", ");
            }
            out.append(value);
        }
        return out.append(']').toString();
    }

    private static void field(StringBuilder json, String name, String value, boolean top, boolean comma) {
        field(json, name, value, top, comma, top ? 2 : 6);
    }

    private static void field(StringBuilder json, String name, String value, boolean top, boolean comma, int indent) {
        json.append(" ".repeat(indent)).append("\"").append(name).append("\": ").append(value);
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }
}
