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

public final class SmalPairwiseDiffAnalyzer {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int BYTE_GAP = 8;
    private static final int MIN_REGION_START = 60_000_000;

    private SmalPairwiseDiffAnalyzer() {
    }

    public static void main(String[] args) throws Exception {
        List<Path> saves = List.of(
                Path.of("games/Small_finishing_only.fm"),
                Path.of("games/Small_pace_only.fm"),
                Path.of("games/Small_concentration_only.fm"),
                Path.of("games/Small_controversy_only.fm"),
                Path.of("games/Small_potential_ability_only.fm"),
                Path.of("games/Small_striker_only.fm"),
                Path.of("games/Small_contract_end_only.fm"),
                Path.of("games/Small_date_of_birth_only.fm")
        );
        List<LoadedSave> loaded = new ArrayList<>();
        for (Path save : saves) {
            loaded.add(new LoadedSave(save, loadPayload(save)));
        }

        StringBuilder json = new StringBuilder(32000);
        json.append("{\n  \"pairs\": [\n");
        int rendered = 0;
        for (int i = 0; i < loaded.size(); i++) {
            for (int j = i + 1; j < loaded.size(); j++) {
                List<DiffRegion> regions = diffRegions(loaded.get(i).payload(), loaded.get(j).payload());
                json.append("    {\n");
                field(json, "left", quote(loaded.get(i).save().toString()), false, true);
                field(json, "right", quote(loaded.get(j).save().toString()), false, true);
                field(json, "regionCount", Integer.toString(regions.size()), false, true);
                json.append("      \"regions\": [\n");
                for (int k = 0; k < Math.min(regions.size(), 12); k++) {
                    DiffRegion region = regions.get(k);
                    json.append("        {\"start\": ").append(region.start())
                            .append(", \"end\": ").append(region.end())
                            .append(", \"length\": ").append(region.length()).append("}");
                    if (k + 1 < Math.min(regions.size(), 12)) {
                        json.append(',');
                    }
                    json.append('\n');
                }
                json.append("      ]\n");
                json.append("    }");
                rendered++;
                if (rendered < (loaded.size() * (loaded.size() - 1)) / 2) {
                    json.append(',');
                }
                json.append('\n');
            }
        }
        json.append("  ]\n}\n");
        System.out.print(json);
    }

    private static List<DiffRegion> diffRegions(byte[] left, byte[] right) {
        int max = Math.min(left.length, right.length);
        List<DiffRegion> regions = new ArrayList<>();
        int start = -1;
        for (int i = 0; i < max; i++) {
            if (left[i] != right[i]) {
                if (start < 0) {
                    start = i;
                }
            } else if (start >= 0) {
                appendRegion(regions, start, i);
                start = -1;
            }
        }
        if (start >= 0) {
            appendRegion(regions, start, max);
        }
        return regions.stream()
                .filter(region -> region.start() >= MIN_REGION_START)
                .sorted(Comparator.comparingInt(DiffRegion::length).reversed().thenComparingInt(DiffRegion::start))
                .toList();
    }

    private static void appendRegion(List<DiffRegion> regions, int start, int end) {
        if (regions.isEmpty()) {
            regions.add(new DiffRegion(start, end));
            return;
        }
        DiffRegion previous = regions.getLast();
        if (start - previous.end() <= BYTE_GAP) {
            regions.set(regions.size() - 1, new DiffRegion(previous.start(), end));
        } else {
            regions.add(new DiffRegion(start, end));
        }
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

    private record LoadedSave(Path save, byte[] payload) {
    }

    private record DiffRegion(int start, int end) {
        private int length() {
            return end - start;
        }
    }
}
