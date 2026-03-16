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

public final class SmalFocusedPairProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int MIN_OFFSET = 60_000_000;

    private SmalFocusedPairProbe() {
    }

    public static void main(String[] args) throws Exception {
        List<PairDef> pairs = List.of(
                new PairDef("finishing_vs_pace", Path.of("games/Small_finishing_only.fm"), Path.of("games/Small_pace_only.fm")),
                new PairDef("concentration_vs_controversy", Path.of("games/Small_concentration_only.fm"), Path.of("games/Small_controversy_only.fm")),
                new PairDef("contract_end_vs_date_of_birth", Path.of("games/Small_contract_end_only.fm"), Path.of("games/Small_date_of_birth_only.fm"))
        );

        StringBuilder json = new StringBuilder(24000);
        json.append("{\n  \"pairs\": [\n");
        for (int i = 0; i < pairs.size(); i++) {
            PairDef pair = pairs.get(i);
            byte[] left = loadPayload(pair.left());
            byte[] right = loadPayload(pair.right());
            List<ByteDiff> diffs = diffs(left, right);
            json.append("    {\n");
            field(json, "name", quote(pair.name()), false, true);
            field(json, "left", quote(pair.left().toString()), false, true);
            field(json, "right", quote(pair.right().toString()), false, true);
            field(json, "diffCount", Integer.toString(diffs.size()), false, true);
            json.append("      \"diffs\": [\n");
            for (int j = 0; j < Math.min(diffs.size(), 80); j++) {
                ByteDiff diff = diffs.get(j);
                json.append("        {\"offset\": ").append(diff.offset())
                        .append(", \"left\": ").append(diff.left())
                        .append(", \"right\": ").append(diff.right())
                        .append("}");
                if (j + 1 < Math.min(diffs.size(), 80)) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            if (i + 1 < pairs.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n}\n");
        System.out.print(json);
    }

    private static List<ByteDiff> diffs(byte[] left, byte[] right) {
        List<ByteDiff> diffs = new ArrayList<>();
        int max = Math.min(left.length, right.length);
        for (int i = MIN_OFFSET; i < max; i++) {
            if (left[i] != right[i]) {
                diffs.add(new ByteDiff(i, left[i] & 0xFF, right[i] & 0xFF));
            }
        }
        return diffs;
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

    private static void field(StringBuilder json, String name, String value, boolean top, boolean comma) {
        json.append(top ? "  " : "      ").append(quote(name)).append(": ").append(value);
        if (comma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private record PairDef(String name, Path left, Path right) {
    }

    private record ByteDiff(int offset, int left, int right) {
    }
}
