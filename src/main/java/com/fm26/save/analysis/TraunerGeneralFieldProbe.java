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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class TraunerGeneralFieldProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_SIZE = 1024;
    private static final int WINDOW_STEP = 16;
    private static final int SEARCH_AHEAD = 8_192;
    private static final int MAX_MATCHES_PER_ENCODING = 64;
    private static final int CONTEXT = 16;

    private TraunerGeneralFieldProbe() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        Map<String, FieldChange> changes = loadChanges(inputs.generalCsv());
        byte[] base = loadPayload(inputs.baseSave());

        StringBuilder json = new StringBuilder(24576);
        json.append("{\n");
        field(json, "baseSave", quote(inputs.baseSave().toString()), true, true);
        field(json, "generalCsv", quote(inputs.generalCsv().toString()), true, true);
        field(json, "saveDir", quote(inputs.saveDir().toString()), true, true);
        field(json, "baseSize", Integer.toString(base.length), true, true);
        json.append("  \"results\": [\n");

        int resultIndex = 0;
        for (Map.Entry<String, FieldChange> entry : changes.entrySet()) {
            Path save = inputs.saveDir().resolve("Trauner_" + slug(entry.getKey()) + "_only.fm");
            if (!Files.exists(save)) {
                continue;
            }

            byte[] target = loadPayload(save);
            Alignment alignment = detectAlignment(base, target);
            List<EncodingMatches> encodingMatches = findMatches(base, target, alignment, entry.getValue());

            json.append("    {\n");
            field(json, "attribute", quote(entry.getKey()), false, true);
            field(json, "save", quote(save.toString()), false, true);
            field(json, "from", Integer.toString(entry.getValue().from()), false, true);
            field(json, "to", Integer.toString(entry.getValue().to()), false, true);
            field(json, "shift", Integer.toString(alignment.shift()), false, true);
            json.append("      \"encodings\": [\n");
            for (int i = 0; i < encodingMatches.size(); i++) {
                EncodingMatches matches = encodingMatches.get(i);
                json.append("        {\n");
                field(json, "encoding", quote(matches.encoding()), false, true, 10);
                field(json, "matchCount", Integer.toString(matches.matches().size()), false, true, 10);
                json.append("          \"matches\": [\n");
                for (int j = 0; j < matches.matches().size(); j++) {
                    OffsetMatch match = matches.matches().get(j);
                    json.append("            {\n");
                    field(json, "offset", Integer.toString(match.offset()), false, true, 12);
                    field(json, "beforeHex", quote(match.beforeHex()), false, true, 12);
                    field(json, "afterHex", quote(match.afterHex()), false, true, 12);
                    field(json, "beforeContext", quote(match.beforeContext()), false, true, 12);
                    field(json, "afterContext", quote(match.afterContext()), false, false, 12);
                    json.append("            }");
                    if (j + 1 < matches.matches().size()) {
                        json.append(',');
                    }
                    json.append('\n');
                }
                json.append("          ]\n");
                json.append("        }");
                if (i + 1 < encodingMatches.size()) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            resultIndex++;
            if (resultIndex < changes.size()) {
                json.append(',');
            }
            json.append('\n');
        }

        json.append("  ]\n");
        json.append("}\n");
        System.out.print(json);
    }

    private static List<EncodingMatches> findMatches(byte[] base, byte[] target, Alignment alignment, FieldChange change) {
        List<EncodingMatches> results = new ArrayList<>();
        results.add(scan(base, target, alignment, "u8_raw", bytes(change.from()), bytes(change.to())));
        results.add(scan(base, target, alignment, "u8_minus_1", bytes(change.from() - 1), bytes(change.to() - 1)));
        results.add(scan(base, target, alignment, "u16_le_raw", bytes16le(change.from()), bytes16le(change.to())));
        results.add(scan(base, target, alignment, "u16_le_minus_1", bytes16le(change.from() - 1), bytes16le(change.to() - 1)));
        results.add(scan(base, target, alignment, "u16_be_raw", bytes16be(change.from()), bytes16be(change.to())));
        results.add(scan(base, target, alignment, "u32_le_raw", bytes32le(change.from()), bytes32le(change.to())));
        return results;
    }

    private static EncodingMatches scan(byte[] base, byte[] target, Alignment alignment, String encoding, byte[] beforePattern, byte[] afterPattern) {
        List<OffsetMatch> matches = new ArrayList<>();
        if (beforePattern.length == 0 || afterPattern.length == 0 || beforePattern.length != afterPattern.length) {
            return new EncodingMatches(encoding, matches);
        }
        int limit = Math.min(base.length, target.length - alignment.shift()) - beforePattern.length;
        for (int offset = alignment.alignedStart(); offset <= limit; offset++) {
            if (matchesPattern(base, offset, beforePattern) && matchesPattern(target, offset + alignment.shift(), afterPattern)) {
                byte[] beforeContextBytes = slice(base, offset - CONTEXT, offset + beforePattern.length + CONTEXT);
                byte[] afterContextBytes = slice(target, offset + alignment.shift() - CONTEXT, offset + alignment.shift() + afterPattern.length + CONTEXT);
                if (!looksBinary(beforeContextBytes) || !looksBinary(afterContextBytes)) {
                    continue;
                }
                matches.add(new OffsetMatch(
                        offset,
                        hex(slice(base, offset, offset + beforePattern.length)),
                        hex(slice(target, offset + alignment.shift(), offset + alignment.shift() + afterPattern.length)),
                        hex(beforeContextBytes),
                        hex(afterContextBytes)
                ));
                if (matches.size() >= MAX_MATCHES_PER_ENCODING) {
                    break;
                }
            }
        }
        return new EncodingMatches(encoding, matches);
    }

    private static boolean matchesPattern(byte[] source, int offset, byte[] pattern) {
        if (offset < 0 || offset + pattern.length > source.length) {
            return false;
        }
        for (int i = 0; i < pattern.length; i++) {
            if (source[offset + i] != pattern[i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] bytes(int value) {
        if (value < 0 || value > 0xFF) {
            return new byte[0];
        }
        return new byte[]{(byte) value};
    }

    private static byte[] bytes16le(int value) {
        if (value < 0 || value > 0xFFFF) {
            return new byte[0];
        }
        return new byte[]{(byte) (value & 0xFF), (byte) ((value >>> 8) & 0xFF)};
    }

    private static byte[] bytes16be(int value) {
        if (value < 0 || value > 0xFFFF) {
            return new byte[0];
        }
        return new byte[]{(byte) ((value >>> 8) & 0xFF), (byte) (value & 0xFF)};
    }

    private static byte[] bytes32le(int value) {
        return new byte[]{
                (byte) (value & 0xFF),
                (byte) ((value >>> 8) & 0xFF),
                (byte) ((value >>> 16) & 0xFF),
                (byte) ((value >>> 24) & 0xFF)
        };
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

    private static Map<String, FieldChange> loadChanges(Path csv) throws IOException {
        Map<String, FieldChange> changes = new LinkedHashMap<>();
        for (String rawLine : Files.readAllLines(csv, StandardCharsets.UTF_8)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("name")) {
                continue;
            }
            String[] parts = line.split(",", 3);
            if (parts.length != 3) {
                throw new IOException("Invalid CSV row: " + line);
            }
            changes.put(parts[0], new FieldChange(Integer.parseInt(parts[1]), Integer.parseInt(parts[2])));
        }
        return changes;
    }

    private static String slug(String attribute) {
        return attribute.toLowerCase(Locale.ROOT).replace(' ', '_');
    }

    private static Alignment detectAlignment(byte[] before, byte[] after) {
        int prefix = commonPrefix(before, after);
        int searchStart = Math.min(prefix + 128, before.length - WINDOW_SIZE - 1);
        for (int probe = searchStart; probe + WINDOW_SIZE + 4096 < Math.min(before.length, 2_000_000); probe += WINDOW_STEP) {
            int hit = indexOf(after, before, probe, probe + WINDOW_SIZE, probe, SEARCH_AHEAD);
            if (hit > probe && matchesAt(before, after, probe, hit, 4096)) {
                return new Alignment(prefix, probe, hit - probe);
            }
        }
        return new Alignment(prefix, prefix, 0);
    }

    private static int commonPrefix(byte[] left, byte[] right) {
        int max = Math.min(left.length, right.length);
        int i = 0;
        while (i < max && left[i] == right[i]) {
            i++;
        }
        return i;
    }

    private static int indexOf(byte[] haystack, byte[] needleSource, int needleStart, int needleEnd, int searchStart, int searchDistance) {
        int maxStart = Math.min(haystack.length - (needleEnd - needleStart), searchStart + searchDistance);
        for (int i = Math.max(0, searchStart); i <= maxStart; i++) {
            boolean matches = true;
            for (int j = 0; j < needleEnd - needleStart; j++) {
                if (haystack[i + j] != needleSource[needleStart + j]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return i;
            }
        }
        return -1;
    }

    private static boolean matchesAt(byte[] before, byte[] after, int beforeStart, int afterStart, int length) {
        if (beforeStart + length > before.length || afterStart + length > after.length) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            if (before[beforeStart + i] != after[afterStart + i]) {
                return false;
            }
        }
        return true;
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

    private static boolean looksBinary(byte[] bytes) {
        if (bytes.length == 0) {
            return false;
        }
        int printable = 0;
        for (byte value : bytes) {
            int c = value & 0xFF;
            if (c >= 32 && c <= 126) {
                printable++;
            }
        }
        return printable * 4 < bytes.length;
    }

    private static void field(StringBuilder json, String name, String value, boolean topLevel, boolean trailingComma) {
        field(json, name, value, topLevel, trailingComma, topLevel ? 2 : 6);
    }

    private static void field(StringBuilder json, String name, String value, boolean topLevel, boolean trailingComma, int indent) {
        json.append(" ".repeat(indent))
                .append(quote(name))
                .append(": ")
                .append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    private record Inputs(Path baseSave, Path generalCsv, Path saveDir) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 3) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]));
            }
            if (args.length == 0) {
                return new Inputs(
                        Path.of("games/Feyenoord_after.fm"),
                        Path.of("general.csv"),
                        Path.of("games")
                );
            }
            throw new IllegalArgumentException(
                    "Usage: TraunerGeneralFieldProbe <base_save.fm> <general.csv> <games_dir>"
            );
        }
    }

    private record FieldChange(int from, int to) {
    }

    private record Alignment(int commonPrefix, int alignedStart, int shift) {
    }

    private record EncodingMatches(String encoding, List<OffsetMatch> matches) {
    }

    private record OffsetMatch(int offset, String beforeHex, String afterHex, String beforeContext, String afterContext) {
    }
}
