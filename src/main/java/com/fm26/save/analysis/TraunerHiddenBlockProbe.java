package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class TraunerHiddenBlockProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int REFERENCE_OFFSET = 66_592_299;
    private static final int BLOCK_LENGTH = 96;
    private static final int SEARCH_RADIUS = 250_000;

    private TraunerHiddenBlockProbe() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        Map<String, PlayerChange> changes = loadChanges(inputs.hiddenCsv());

        byte[] referencePayload = loadPayload(inputs.referenceSave());
        byte[] referenceBlock = slice(referencePayload, REFERENCE_OFFSET, REFERENCE_OFFSET + BLOCK_LENGTH);

        byte[] basePayload = loadPayload(inputs.baseSave());
        MatchWindow baseWindow = locateBestWindow(basePayload, referenceBlock, REFERENCE_OFFSET, SEARCH_RADIUS);
        byte[] baseBlock = slice(basePayload, baseWindow.offset(), baseWindow.offset() + BLOCK_LENGTH);

        List<ProbeResult> probes = new ArrayList<>();
        for (Map.Entry<String, PlayerChange> entry : changes.entrySet()) {
            String attribute = entry.getKey();
            Path save = resolveSave(inputs.saveDir(), attribute);
            if (!Files.exists(save)) {
                continue;
            }
            byte[] payload = loadPayload(save);
            MatchWindow window = locateBestWindow(payload, referenceBlock, REFERENCE_OFFSET, SEARCH_RADIUS);
            byte[] block = slice(payload, window.offset(), window.offset() + BLOCK_LENGTH);
            probes.add(new ProbeResult(attribute, entry.getValue(), save, window, block, diffSlots(baseBlock, block)));
        }

        probes.sort(Comparator.comparing(ProbeResult::attribute));
        System.out.println(renderJson(inputs, baseWindow, referenceBlock, baseBlock, probes));
    }

    private static Path resolveSave(Path saveDir, String attribute) {
        String baseName = "Trauner_" + attribute + "_only.fm";
        Path direct = saveDir.resolve(baseName);
        if (Files.exists(direct)) {
            return direct;
        }
        if ("adaptability".equals(attribute)) {
            Path preferred = saveDir.resolve("Trauner_adaptability_only_20.fm");
            if (Files.exists(preferred)) {
                return preferred;
            }
        }
        return direct;
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

    private static Map<String, PlayerChange> loadChanges(Path csv) throws IOException {
        Map<String, PlayerChange> changes = new LinkedHashMap<>();
        for (String rawLine : Files.readAllLines(csv, StandardCharsets.UTF_8)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("name")) {
                continue;
            }
            String[] parts = line.split(",", 3);
            if (parts.length != 3) {
                throw new IOException("Invalid CSV row: " + line);
            }
            changes.put(parts[0], new PlayerChange(parts[0], Integer.parseInt(parts[1]), Integer.parseInt(parts[2])));
        }
        if (!changes.containsKey("temperament")) {
            changes.put("temperament", new PlayerChange("temperament", 6, 13));
        }
        return changes;
    }

    private static byte[] slice(byte[] bytes, int from, int to) {
        int start = Math.max(0, from);
        int end = Math.min(bytes.length, to);
        byte[] copy = new byte[Math.max(0, end - start)];
        if (copy.length > 0) {
            System.arraycopy(bytes, start, copy, 0, copy.length);
        }
        return copy;
    }

    private static MatchWindow locateBestWindow(byte[] payload, byte[] template, int centerOffset, int radius) {
        int start = Math.max(0, centerOffset - radius);
        int end = Math.min(payload.length - template.length, centerOffset + radius);
        int bestOffset = centerOffset;
        int bestScore = -1;
        for (int offset = start; offset <= end; offset++) {
            int score = 0;
            for (int i = 0; i < template.length; i++) {
                if (payload[offset + i] == template[i]) {
                    score++;
                }
            }
            if (score > bestScore) {
                bestScore = score;
                bestOffset = offset;
            }
        }
        return new MatchWindow(bestOffset, bestScore, template.length);
    }

    private static List<DiffSlot> diffSlots(byte[] baseBlock, byte[] targetBlock) {
        List<DiffSlot> slots = new ArrayList<>();
        int length = Math.min(baseBlock.length, targetBlock.length);
        for (int i = 0; i < length; i++) {
            int before = baseBlock[i] & 0xFF;
            int after = targetBlock[i] & 0xFF;
            if (before != after) {
                slots.add(new DiffSlot(i, before, after));
            }
        }
        return slots;
    }

    private static String renderJson(
            Inputs inputs,
            MatchWindow baseWindow,
            byte[] referenceBlock,
            byte[] baseBlock,
            List<ProbeResult> probes
    ) {
        StringBuilder json = new StringBuilder(32_000);
        json.append("{\n");
        field(json, "baseSave", quote(inputs.baseSave().toString()), true, true);
        field(json, "referenceSave", quote(inputs.referenceSave().toString()), true, true);
        field(json, "hiddenCsv", quote(inputs.hiddenCsv().toString()), true, true);
        field(json, "saveDir", quote(inputs.saveDir().toString()), true, true);
        field(json, "referenceOffset", Integer.toString(REFERENCE_OFFSET), true, true);
        field(json, "blockLength", Integer.toString(BLOCK_LENGTH), true, true);
        field(json, "resolvedBaseOffset", Integer.toString(baseWindow.offset()), true, true);
        field(json, "resolvedBaseMatchScore", Integer.toString(baseWindow.score()), true, true);
        field(json, "referenceHex", quote(hex(referenceBlock)), true, true);
        field(json, "baseHex", quote(hex(baseBlock)), true, true);
        field(json, "baseAscii", quote(ascii(baseBlock)), true, true);

        json.append("  \"probes\": [\n");
        for (int i = 0; i < probes.size(); i++) {
            ProbeResult probe = probes.get(i);
            json.append("    {\n");
            field(json, "attribute", quote(probe.attribute()), false, true);
            field(json, "save", quote(probe.save().toString()), false, true);
            field(json, "from", Integer.toString(probe.change().from()), false, true);
            field(json, "to", Integer.toString(probe.change().to()), false, true);
            field(json, "resolvedOffset", Integer.toString(probe.window().offset()), false, true);
            field(json, "matchScore", Integer.toString(probe.window().score()), false, true);
            field(json, "blockHex", quote(hex(probe.block())), false, true);
            field(json, "blockAscii", quote(ascii(probe.block())), false, true);
            json.append("      \"changedSlots\": [\n");
            for (int j = 0; j < probe.diffSlots().size(); j++) {
                DiffSlot slot = probe.diffSlots().get(j);
                json.append("        {")
                        .append("\"relativeOffset\": ").append(slot.relativeOffset()).append(", ")
                        .append("\"absoluteOffset\": ").append(probe.window().offset() + slot.relativeOffset()).append(", ")
                        .append("\"before\": ").append(slot.before()).append(", ")
                        .append("\"after\": ").append(slot.after())
                        .append("}");
                if (j + 1 < probe.diffSlots().size()) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            if (i + 1 < probes.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private static void field(StringBuilder json, String name, String value, boolean indent, boolean trailingComma) {
        if (indent) {
            json.append("  ");
        } else {
            json.append("      ");
        }
        json.append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                builder.append(' ');
            }
            builder.append(String.format(Locale.ROOT, "%02x", bytes[i] & 0xFF));
        }
        return builder.toString();
    }

    private static String ascii(byte[] bytes) {
        StringBuilder ascii = new StringBuilder(bytes.length);
        for (byte value : bytes) {
            int c = value & 0xFF;
            if (c >= 32 && c <= 126) {
                ascii.append((char) c);
            } else {
                ascii.append('.');
            }
        }
        return ascii.toString();
    }

    private static String quote(String value) {
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private record Inputs(Path baseSave, Path referenceSave, Path hiddenCsv, Path saveDir) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 4) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]), Path.of(args[3]));
            }
            if (args.length == 0) {
                return new Inputs(
                        Path.of("games/Feyenoord_after.fm"),
                        Path.of("games/Trauner_adaptability_only_10.fm"),
                        Path.of("hidden.csv"),
                        Path.of("games")
                );
            }
            throw new IllegalArgumentException(
                    "Usage: TraunerHiddenBlockProbe <base_save.fm> <reference_save.fm> <hidden.csv> <save_dir>"
            );
        }
    }

    private record MatchWindow(int offset, int score, int templateLength) {
    }

    private record PlayerChange(String name, int from, int to) {
    }

    private record ProbeResult(
            String attribute,
            PlayerChange change,
            Path save,
            MatchWindow window,
            byte[] block,
            List<DiffSlot> diffSlots
    ) {
    }

    private record DiffSlot(int relativeOffset, int before, int after) {
    }
}
