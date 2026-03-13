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

public final class TraunerProfileJsonExporter {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int BLOCK_OFFSET = 66_582_080;
    private static final int BLOCK_LENGTH = 81;
    private static final int SEARCH_RADIUS = 250_000;
    private static final int TRAUNER_PLAYER_ID = 16_023_929;

    private static final List<FieldMapping> FIELD_MAPPINGS = List.of(
            new FieldMapping("finishing", 0, ValueEncoding.TIMES_FIVE),
            new FieldMapping("corners", 25, ValueEncoding.TIMES_FIVE),
            new FieldMapping("aggression", 43, ValueEncoding.TIMES_FIVE),
            new FieldMapping("agility", 44, ValueEncoding.TIMES_FIVE),
            new FieldMapping("versatility", 47, ValueEncoding.TIMES_FIVE),
            new FieldMapping("height", 80, ValueEncoding.RAW)
    );

    private TraunerProfileJsonExporter() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] referencePayload = loadPayload(inputs.referenceSave());
        byte[] targetPayload = loadPayload(inputs.targetSave());

        byte[] referenceBlock = slice(referencePayload, BLOCK_OFFSET, BLOCK_OFFSET + BLOCK_LENGTH);
        MatchWindow targetWindow = locateBestWindow(targetPayload, referenceBlock, BLOCK_OFFSET, SEARCH_RADIUS);
        byte[] targetBlock = slice(targetPayload, targetWindow.offset(), targetWindow.offset() + BLOCK_LENGTH);

        System.out.println(renderJson(inputs, referencePayload.length, targetPayload.length, targetWindow, targetBlock));
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
            MatchWindow targetWindow,
            byte[] targetBlock
    ) {
        StringBuilder json = new StringBuilder(4096);
        json.append("{\n");
        appendField(json, "playerId", Integer.toString(TRAUNER_PLAYER_ID), true);
        appendField(json, "name", quote("Gernot Trauner"), true);
        appendField(json, "club", quote("Feyenoord"), true);
        appendField(json, "referenceSave", quote(inputs.referenceSave().toString()), true);
        appendField(json, "targetSave", quote(inputs.targetSave().toString()), true);
        appendField(json, "referencePayloadSize", Integer.toString(referencePayloadSize), true);
        appendField(json, "targetPayloadSize", Integer.toString(targetPayloadSize), true);
        appendField(json, "blockOffset", Integer.toString(targetWindow.offset()), true);
        appendField(json, "blockLength", Integer.toString(BLOCK_LENGTH), true);
        appendField(json, "matchScore", Integer.toString(targetWindow.score()), true);
        appendField(json, "matchRatio", String.format(Locale.ROOT, "%.4f", targetWindow.ratio()), true);
        appendField(json, "blockHex", quote(hex(targetBlock)), true);
        json.append("  \"attributes\": {\n");
        for (int i = 0; i < FIELD_MAPPINGS.size(); i++) {
            FieldMapping mapping = FIELD_MAPPINGS.get(i);
            int stored = targetBlock[mapping.relativeOffset()] & 0xFF;
            Integer decoded = mapping.encoding().decode(stored);
            json.append("    ").append(quote(mapping.name())).append(": {\n");
            appendNestedField(json, "relativeOffset", Integer.toString(mapping.relativeOffset()), true);
            appendNestedField(json, "absoluteOffset", Integer.toString(targetWindow.offset() + mapping.relativeOffset()), true);
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
                        Path.of("games/Feyenoord_more_after.fm")
                );
            }
            throw new IllegalArgumentException(
                    "Usage: TraunerProfileJsonExporter <reference_after.fm> <target.fm>"
            );
        }
    }

    private record MatchWindow(int offset, int score, int templateLength) {
        private double ratio() {
            return templateLength == 0 ? 0.0 : (double) score / templateLength;
        }
    }

    private record FieldMapping(String name, int relativeOffset, ValueEncoding encoding) {
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
