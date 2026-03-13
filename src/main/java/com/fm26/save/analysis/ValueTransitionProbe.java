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

public final class ValueTransitionProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int WINDOW_SIZE = 1024;
    private static final int WINDOW_STEP = 16;
    private static final int SEARCH_AHEAD = 8_192;
    private static final int CONTEXT = 16;
    private static final int MAX_MATCHES = 64;

    private ValueTransitionProbe() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("Usage: ValueTransitionProbe <base_save.fm> <target_save.fm> <from> <to>");
        }
        Path baseSave = Path.of(args[0]);
        Path targetSave = Path.of(args[1]);
        int from = Integer.parseInt(args[2]);
        int to = Integer.parseInt(args[3]);

        byte[] base = loadPayload(baseSave);
        byte[] target = loadPayload(targetSave);
        Alignment alignment = detectAlignment(base, target);

        List<EncodingMatches> matches = List.of(
                scan(base, target, alignment, "u8_raw", bytes(from), bytes(to)),
                scan(base, target, alignment, "u16_le_raw", bytes16le(from), bytes16le(to)),
                scan(base, target, alignment, "u8_times_5", bytes(from * 5), bytes(to * 5)),
                scan(base, target, alignment, "u16_le_times_5", bytes16le(from * 5), bytes16le(to * 5))
        );

        StringBuilder json = new StringBuilder(16384);
        json.append("{\n");
        field(json, "baseSave", quote(baseSave.toString()), true, true);
        field(json, "targetSave", quote(targetSave.toString()), true, true);
        field(json, "from", Integer.toString(from), true, true);
        field(json, "to", Integer.toString(to), true, true);
        field(json, "shift", Integer.toString(alignment.shift()), true, true);
        json.append("  \"encodings\": [\n");
        for (int i = 0; i < matches.size(); i++) {
            EncodingMatches encoding = matches.get(i);
            json.append("    {\n");
            field(json, "name", quote(encoding.name()), false, true, 6);
            field(json, "matchCount", Integer.toString(encoding.matches().size()), false, true, 6);
            json.append("      \"matches\": [\n");
            for (int j = 0; j < encoding.matches().size(); j++) {
                Match match = encoding.matches().get(j);
                json.append("        {\n");
                field(json, "offset", Integer.toString(match.offset()), false, true, 8);
                field(json, "beforeHex", quote(match.beforeHex()), false, true, 8);
                field(json, "afterHex", quote(match.afterHex()), false, true, 8);
                field(json, "beforeContext", quote(match.beforeContext()), false, true, 8);
                field(json, "afterContext", quote(match.afterContext()), false, false, 8);
                json.append("        }");
                if (j + 1 < encoding.matches().size()) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            if (i + 1 < matches.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        System.out.print(json);
    }

    private static EncodingMatches scan(byte[] base, byte[] target, Alignment alignment, String name, byte[] beforePattern, byte[] afterPattern) {
        List<Match> matches = new ArrayList<>();
        if (beforePattern.length == 0 || afterPattern.length == 0 || beforePattern.length != afterPattern.length) {
            return new EncodingMatches(name, matches);
        }
        int limit = Math.min(base.length, target.length - alignment.shift()) - beforePattern.length;
        for (int offset = alignment.alignedStart(); offset <= limit; offset++) {
            if (matchesPattern(base, offset, beforePattern) && matchesPattern(target, offset + alignment.shift(), afterPattern)) {
                byte[] beforeContext = slice(base, offset - CONTEXT, offset + beforePattern.length + CONTEXT);
                byte[] afterContext = slice(target, offset + alignment.shift() - CONTEXT, offset + alignment.shift() + afterPattern.length + CONTEXT);
                if (!looksBinary(beforeContext) || !looksBinary(afterContext)) {
                    continue;
                }
                matches.add(new Match(
                        offset,
                        hex(slice(base, offset, offset + beforePattern.length)),
                        hex(slice(target, offset + alignment.shift(), offset + alignment.shift() + afterPattern.length)),
                        hex(beforeContext),
                        hex(afterContext)
                ));
                if (matches.size() >= MAX_MATCHES) {
                    break;
                }
            }
        }
        return new EncodingMatches(name, matches);
    }

    private static boolean looksBinary(byte[] bytes) {
        int printable = 0;
        for (byte value : bytes) {
            int c = value & 0xFF;
            if (c >= 32 && c <= 126) {
                printable++;
            }
        }
        return printable * 4 < bytes.length;
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

    private record Alignment(int commonPrefix, int alignedStart, int shift) {
    }

    private record EncodingMatches(String name, List<Match> matches) {
    }

    private record Match(int offset, String beforeHex, String afterHex, String beforeContext, String afterContext) {
    }
}
