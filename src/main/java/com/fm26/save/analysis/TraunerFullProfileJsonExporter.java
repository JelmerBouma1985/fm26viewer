package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

public final class TraunerFullProfileJsonExporter {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int TRAUNER_PLAYER_ID = 16_023_929;

    private static final BlockDefinition TECHNICAL_PREFIX_BLOCK = new BlockDefinition("technical_prefix", 66_582_078, 83, 250_000);
    private static final BlockDefinition VISIBLE_BLOCK = new BlockDefinition("visible", 66_582_080, 81, 250_000);
    private static final BlockDefinition HIDDEN_BLOCK = new BlockDefinition("hidden", 66_582_989, 96, 250_000);

    private static final List<FieldMapping> FIELD_MAPPINGS = List.of(
            new FieldMapping("crossing", TECHNICAL_PREFIX_BLOCK, 0, ValueEncoding.TIMES_FIVE),
            new FieldMapping("dribbling", TECHNICAL_PREFIX_BLOCK, 1, ValueEncoding.TIMES_FIVE),
            new FieldMapping("finishing", VISIBLE_BLOCK, 0, ValueEncoding.TIMES_FIVE),
            new FieldMapping("heading", VISIBLE_BLOCK, 1, ValueEncoding.TIMES_FIVE),
            new FieldMapping("long shots", VISIBLE_BLOCK, 2, ValueEncoding.TIMES_FIVE),
            new FieldMapping("marking", VISIBLE_BLOCK, 3, ValueEncoding.TIMES_FIVE),
            new FieldMapping("off the ball", VISIBLE_BLOCK, 4, ValueEncoding.TIMES_FIVE),
            new FieldMapping("passing", VISIBLE_BLOCK, 5, ValueEncoding.TIMES_FIVE),
            new FieldMapping("penalty taking", VISIBLE_BLOCK, 6, ValueEncoding.TIMES_FIVE),
            new FieldMapping("tackling", VISIBLE_BLOCK, 7, ValueEncoding.TIMES_FIVE),
            new FieldMapping("vision", VISIBLE_BLOCK, 8, ValueEncoding.TIMES_FIVE),
            new FieldMapping("first touch", VISIBLE_BLOCK, 20, ValueEncoding.TIMES_FIVE),
            new FieldMapping("technique", VISIBLE_BLOCK, 21, ValueEncoding.TIMES_FIVE),
            new FieldMapping("flair", VISIBLE_BLOCK, 24, ValueEncoding.TIMES_FIVE),
            new FieldMapping("corners", VISIBLE_BLOCK, 25, ValueEncoding.TIMES_FIVE),
            new FieldMapping("teamwork", VISIBLE_BLOCK, 26, ValueEncoding.TIMES_FIVE),
            new FieldMapping("work rate", VISIBLE_BLOCK, 27, ValueEncoding.TIMES_FIVE),
            new FieldMapping("long throws", VISIBLE_BLOCK, 28, ValueEncoding.TIMES_FIVE),
            new FieldMapping("acceleration", VISIBLE_BLOCK, 32, ValueEncoding.TIMES_FIVE),
            new FieldMapping("free kicks", VISIBLE_BLOCK, 33, ValueEncoding.TIMES_FIVE),
            new FieldMapping("strength", VISIBLE_BLOCK, 34, ValueEncoding.TIMES_FIVE),
            new FieldMapping("stamina", VISIBLE_BLOCK, 35, ValueEncoding.TIMES_FIVE),
            new FieldMapping("pace", VISIBLE_BLOCK, 36, ValueEncoding.TIMES_FIVE),
            new FieldMapping("jumping reach", VISIBLE_BLOCK, 37, ValueEncoding.TIMES_FIVE),
            new FieldMapping("leadership", VISIBLE_BLOCK, 38, ValueEncoding.TIMES_FIVE),
            new FieldMapping("dirtiness", VISIBLE_BLOCK, 39, ValueEncoding.TIMES_FIVE),
            new FieldMapping("balance", VISIBLE_BLOCK, 40, ValueEncoding.TIMES_FIVE),
            new FieldMapping("bravery", VISIBLE_BLOCK, 41, ValueEncoding.TIMES_FIVE),
            new FieldMapping("consistency", VISIBLE_BLOCK, 42, ValueEncoding.TIMES_FIVE),
            new FieldMapping("aggression", VISIBLE_BLOCK, 43, ValueEncoding.TIMES_FIVE),
            new FieldMapping("agility", VISIBLE_BLOCK, 44, ValueEncoding.TIMES_FIVE),
            new FieldMapping("important matches", VISIBLE_BLOCK, 45, ValueEncoding.TIMES_FIVE),
            new FieldMapping("injury proneness", VISIBLE_BLOCK, 46, ValueEncoding.TIMES_FIVE),
            new FieldMapping("versatility", VISIBLE_BLOCK, 47, ValueEncoding.TIMES_FIVE),
            new FieldMapping("natural fitness", VISIBLE_BLOCK, 48, ValueEncoding.TIMES_FIVE),
            new FieldMapping("determination", VISIBLE_BLOCK, 49, ValueEncoding.TIMES_FIVE),
            new FieldMapping("composure", VISIBLE_BLOCK, 50, ValueEncoding.TIMES_FIVE),
            new FieldMapping("concentration", VISIBLE_BLOCK, 51, ValueEncoding.TIMES_FIVE),
            new FieldMapping("height", VISIBLE_BLOCK, 80, ValueEncoding.RAW),
            new FieldMapping("anticipation", VISIBLE_BLOCK, 15, ValueEncoding.TIMES_FIVE),
            new FieldMapping("decisions", VISIBLE_BLOCK, 16, ValueEncoding.TIMES_FIVE),
            new FieldMapping("positioning", VISIBLE_BLOCK, 18, ValueEncoding.TIMES_FIVE),
            new FieldMapping("adaptability", HIDDEN_BLOCK, 47, ValueEncoding.RAW),
            new FieldMapping("ambition", HIDDEN_BLOCK, 48, ValueEncoding.RAW),
            new FieldMapping("loyalty", HIDDEN_BLOCK, 49, ValueEncoding.RAW),
            new FieldMapping("pressure", HIDDEN_BLOCK, 50, ValueEncoding.RAW),
            new FieldMapping("professionalism", HIDDEN_BLOCK, 51, ValueEncoding.RAW),
            new FieldMapping("sportmanship", HIDDEN_BLOCK, 52, ValueEncoding.RAW),
            new FieldMapping("temperament", HIDDEN_BLOCK, 53, ValueEncoding.RAW),
            new FieldMapping("controversy", HIDDEN_BLOCK, 54, ValueEncoding.RAW)
    );

    private TraunerFullProfileJsonExporter() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] referencePayload = loadPayload(inputs.referenceSave());
        byte[] targetPayload = loadPayload(inputs.targetSave());

        byte[] technicalPrefixReference = slice(referencePayload, TECHNICAL_PREFIX_BLOCK.referenceOffset(), TECHNICAL_PREFIX_BLOCK.referenceOffset() + TECHNICAL_PREFIX_BLOCK.length());
        MatchWindow technicalPrefixWindow = locateBestWindow(targetPayload, technicalPrefixReference, TECHNICAL_PREFIX_BLOCK.referenceOffset(), TECHNICAL_PREFIX_BLOCK.searchRadius());
        byte[] technicalPrefixTarget = slice(targetPayload, technicalPrefixWindow.offset(), technicalPrefixWindow.offset() + TECHNICAL_PREFIX_BLOCK.length());

        byte[] visibleReference = slice(referencePayload, VISIBLE_BLOCK.referenceOffset(), VISIBLE_BLOCK.referenceOffset() + VISIBLE_BLOCK.length());
        MatchWindow visibleWindow = locateBestWindow(targetPayload, visibleReference, VISIBLE_BLOCK.referenceOffset(), VISIBLE_BLOCK.searchRadius());
        byte[] visibleTarget = slice(targetPayload, visibleWindow.offset(), visibleWindow.offset() + VISIBLE_BLOCK.length());

        byte[] hiddenReference = slice(referencePayload, HIDDEN_BLOCK.referenceOffset(), HIDDEN_BLOCK.referenceOffset() + HIDDEN_BLOCK.length());
        MatchWindow hiddenWindow = locateBestWindow(targetPayload, hiddenReference, HIDDEN_BLOCK.referenceOffset(), HIDDEN_BLOCK.searchRadius());
        byte[] hiddenTarget = slice(targetPayload, hiddenWindow.offset(), hiddenWindow.offset() + HIDDEN_BLOCK.length());

        System.out.println(renderJson(
                inputs,
                referencePayload.length,
                targetPayload.length,
                technicalPrefixWindow,
                technicalPrefixTarget,
                visibleWindow,
                visibleTarget,
                hiddenWindow,
                hiddenTarget
        ));
    }

    private static byte[] loadPayload(Path path) throws IOException {
        if (!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".fm")) {
            return Files.readAllBytes(path);
        }
        try (InputStream raw = new BufferedInputStream(Files.newInputStream(path));
             InputStream skipped = skipFully(raw, FMF_ZSTD_OFFSET);
             ZstdInputStream zstd = new ZstdInputStream(skipped)) {
            return readZstdStream(zstd);
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

    private static byte[] readZstdStream(ZstdInputStream zstd) throws IOException {
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

    private static String renderJson(
            Inputs inputs,
            int referencePayloadSize,
            int targetPayloadSize,
            MatchWindow technicalPrefixWindow,
            byte[] technicalPrefixTarget,
            MatchWindow visibleWindow,
            byte[] visibleTarget,
            MatchWindow hiddenWindow,
            byte[] hiddenTarget
    ) {
        StringBuilder json = new StringBuilder(8192);
        json.append("{\n");
        appendField(json, "playerId", Integer.toString(TRAUNER_PLAYER_ID), true);
        appendField(json, "name", quote("Gernot Trauner"), true);
        appendField(json, "club", quote("Feyenoord"), true);
        appendField(json, "referenceSave", quote(inputs.referenceSave().toString()), true);
        appendField(json, "targetSave", quote(inputs.targetSave().toString()), true);
        appendField(json, "referencePayloadSize", Integer.toString(referencePayloadSize), true);
        appendField(json, "targetPayloadSize", Integer.toString(targetPayloadSize), true);

        json.append("  \"blocks\": {\n");
        renderBlock(json, "technical_prefix", TECHNICAL_PREFIX_BLOCK, technicalPrefixWindow, technicalPrefixTarget, true);
        renderBlock(json, "visible", VISIBLE_BLOCK, visibleWindow, visibleTarget, true);
        renderBlock(json, "hidden", HIDDEN_BLOCK, hiddenWindow, hiddenTarget, false);
        json.append("  },\n");

        json.append("  \"attributes\": {\n");
        for (int i = 0; i < FIELD_MAPPINGS.size(); i++) {
            FieldMapping mapping = FIELD_MAPPINGS.get(i);
            byte[] block;
            int blockOffset;
            if (mapping.block().name().equals(TECHNICAL_PREFIX_BLOCK.name())) {
                block = technicalPrefixTarget;
                blockOffset = technicalPrefixWindow.offset();
            } else if (mapping.block().name().equals(VISIBLE_BLOCK.name())) {
                block = visibleTarget;
                blockOffset = visibleWindow.offset();
            } else {
                block = hiddenTarget;
                blockOffset = hiddenWindow.offset();
            }
            int stored = block[mapping.relativeOffset()] & 0xFF;
            Integer decoded = mapping.encoding().decode(stored);
            json.append("    ").append(quote(mapping.name())).append(": {\n");
            appendNestedField(json, "block", quote(mapping.block().name()), true);
            appendNestedField(json, "relativeOffset", Integer.toString(mapping.relativeOffset()), true);
            appendNestedField(json, "absoluteOffset", Integer.toString(blockOffset + mapping.relativeOffset()), true);
            appendNestedField(json, "storage", quote(mapping.encoding().jsonName()), true);
            appendNestedField(json, "storedValue", Integer.toString(stored), true);
            appendNestedField(json, "decodedValue", decoded == null ? "null" : Integer.toString(decoded), false);
            json.append("    }");
            if (i + 1 < FIELD_MAPPINGS.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n");
        json.append("}\n");
        return json.toString();
    }

    private static void renderBlock(
            StringBuilder json,
            String name,
            BlockDefinition definition,
            MatchWindow window,
            byte[] block,
            boolean trailingComma
    ) {
        json.append("    ").append(quote(name)).append(": {\n");
        appendNestedField(json, "referenceOffset", Integer.toString(definition.referenceOffset()), true);
        appendNestedField(json, "resolvedOffset", Integer.toString(window.offset()), true);
        appendNestedField(json, "length", Integer.toString(definition.length()), true);
        appendNestedField(json, "matchScore", Integer.toString(window.score()), true);
        appendNestedField(json, "matchRatio", String.format(Locale.ROOT, "%.4f", window.ratio()), true);
        appendNestedField(json, "hex", quote(hex(block)), true);
        appendNestedField(json, "ascii", quote(ascii(block)), false);
        json.append("    }");
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void appendField(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("  ")
                .append(quote(name))
                .append(": ")
                .append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void appendNestedField(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("      ")
                .append(quote(name))
                .append(": ")
                .append(value);
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

    private record Inputs(Path referenceSave, Path targetSave) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 2) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]));
            }
            if (args.length == 0) {
                return new Inputs(
                        Path.of("games/Feyenoord_after.fm"),
                        Path.of("games/Feyenoord_after.fm")
                );
            }
            throw new IllegalArgumentException(
                    "Usage: TraunerFullProfileJsonExporter <reference_after.fm> <target.fm>"
            );
        }
    }

    private record BlockDefinition(String name, int referenceOffset, int length, int searchRadius) {
    }

    private record MatchWindow(int offset, int score, int templateLength) {
        private double ratio() {
            return templateLength == 0 ? 0.0 : (double) score / templateLength;
        }
    }

    private record FieldMapping(String name, BlockDefinition block, int relativeOffset, ValueEncoding encoding) {
    }

    private enum ValueEncoding {
        RAW("raw") {
            @Override
            Integer decode(int stored) {
                return stored;
            }
        },
        TIMES_FIVE("times_five") {
            @Override
            Integer decode(int stored) {
                return stored % 5 == 0 ? stored / 5 : null;
            }
        };

        private final String jsonName;

        ValueEncoding(String jsonName) {
            this.jsonName = jsonName;
        }

        private String jsonName() {
            return jsonName;
        }

        abstract Integer decode(int stored);
    }
}
