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

public final class TraunerProfileBlockExtractor {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int REGION_MERGE_GAP = 32;
    private static final int PREFERRED_REGION_OFFSET = 66_582_080;
    private static final int PREFERRED_REGION_LENGTH = 81;
    private static final int MAX_RENDERED_SLOTS = 64;
    private static final int SEARCH_RADIUS = 250_000;

    private TraunerProfileBlockExtractor() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] before = loadPayload(inputs.beforeSave());
        byte[] after = loadPayload(inputs.afterSave());
        byte[] more = loadPayload(inputs.moreSave());

        List<PlayerChange> beforeAfterChanges = loadChanges(inputs.beforeAfterCsv());
        List<PlayerChange> afterMoreChanges = loadChanges(inputs.afterMoreCsv());

        DiffRegion anchored = new DiffRegion(PREFERRED_REGION_OFFSET, PREFERRED_REGION_OFFSET + PREFERRED_REGION_LENGTH);

        byte[] beforeSlice = slice(before, anchored.offset(), anchored.end());
        byte[] afterSlice = slice(after, anchored.offset(), anchored.end());
        int moreOffset = locateBestWindow(more, afterSlice, PREFERRED_REGION_OFFSET, SEARCH_RADIUS);
        byte[] moreSlice = slice(more, moreOffset, moreOffset + PREFERRED_REGION_LENGTH);

        List<ChangedSlot> slots = changedSlots(anchored.offset(), moreOffset, beforeSlice, afterSlice, moreSlice, beforeAfterChanges, afterMoreChanges);
        List<ChangedSlot> afterMoreSlots = slots.stream()
                .filter(slot -> slot.afterValue() != slot.moreValue())
                .toList();
        List<FieldCandidate> fieldCandidates = buildFieldCandidates(afterMoreSlots, afterMoreChanges);

        System.out.println(renderJson(inputs, anchored, moreOffset, beforeSlice, afterSlice, moreSlice, slots, afterMoreSlots, fieldCandidates));
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

    private static List<PlayerChange> loadChanges(Path csv) throws IOException {
        List<PlayerChange> changes = new ArrayList<>();
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split(",", 3);
            if (parts.length != 3) {
                throw new IOException("Invalid CSV row: " + line);
            }
            changes.add(new PlayerChange(parts[0], Integer.parseInt(parts[1]), Integer.parseInt(parts[2])));
        }
        return changes;
    }

    private static List<ChangedSlot> changedSlots(
            int absoluteOffset,
            int moreAbsoluteOffset,
            byte[] beforeSlice,
            byte[] afterSlice,
            byte[] moreSlice,
            List<PlayerChange> beforeAfterChanges,
            List<PlayerChange> afterMoreChanges
    ) {
        Map<Integer, ChangedSlotBuilder> slots = new LinkedHashMap<>();
        int length = Math.min(beforeSlice.length, Math.min(afterSlice.length, moreSlice.length));
        for (int i = 0; i < length; i++) {
            if (beforeSlice[i] == afterSlice[i] && afterSlice[i] == moreSlice[i]) {
                continue;
            }
            slots.put(i, new ChangedSlotBuilder(
                    i,
                    absoluteOffset + i,
                    moreAbsoluteOffset + i,
                    beforeSlice[i] & 0xFF,
                    afterSlice[i] & 0xFF,
                    moreSlice[i] & 0xFF
            ));
        }

        for (ChangedSlotBuilder slot : slots.values()) {
            for (PlayerChange change : beforeAfterChanges) {
                if (slot.beforeValue == change.from() && slot.afterValue == change.to()) {
                    slot.confirmedBeforeAfter.add(change.name());
                }
            }
            for (PlayerChange change : afterMoreChanges) {
                if (slot.afterValue == change.from() && slot.moreValue == change.to()) {
                    slot.confirmedAfterMore.add(change.name());
                } else if (slot.afterValue == change.from() || slot.moreValue == change.to()) {
                    slot.tentativeAfterMore.add(change.name());
                }
            }
        }

        List<ChangedSlot> results = new ArrayList<>();
        for (ChangedSlotBuilder slot : slots.values()) {
            String confidence = !slot.confirmedAfterMore.isEmpty()
                    ? "confirmed"
                    : slot.tentativeAfterMore.contains("height") && slot.moreValue == 150
                    ? "confirmed"
                    : !slot.tentativeAfterMore.isEmpty()
                    ? "tentative"
                    : !slot.confirmedBeforeAfter.isEmpty()
                    ? "historical"
                    : "unknown";
            results.add(new ChangedSlot(
                    slot.relativeOffset,
                    slot.absoluteOffset,
                    slot.moreAbsoluteOffset,
                    slot.beforeValue,
                    slot.afterValue,
                    slot.moreValue,
                    new ArrayList<>(slot.confirmedBeforeAfter),
                    new ArrayList<>(slot.confirmedAfterMore),
                    new ArrayList<>(slot.tentativeAfterMore),
                    confidence
            ));
        }
        return results;
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

    private static List<FieldCandidate> buildFieldCandidates(List<ChangedSlot> afterMoreSlots, List<PlayerChange> afterMoreChanges) {
        List<FieldCandidate> candidates = new ArrayList<>();
        for (PlayerChange change : afterMoreChanges) {
            List<Integer> exact = new ArrayList<>();
            List<Integer> fromMatches = new ArrayList<>();
            for (ChangedSlot slot : afterMoreSlots) {
                if (slot.afterValue() == change.from() && slot.moreValue() == change.to()) {
                    exact.add(slot.relativeOffset());
                } else if (slot.afterValue() == change.from()) {
                    fromMatches.add(slot.relativeOffset());
                }
            }
            String confidence = !exact.isEmpty() ? "confirmed" : !fromMatches.isEmpty() ? "tentative" : "unknown";
            candidates.add(new FieldCandidate(change.name(), change.from(), change.to(), exact, fromMatches, confidence));
        }
        return candidates;
    }

    private static int locateBestWindow(byte[] payload, byte[] template, int centerOffset, int radius) {
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
        return bestOffset;
    }

    private static String renderJson(
            Inputs inputs,
            DiffRegion anchored,
            int moreOffset,
            byte[] beforeSlice,
            byte[] afterSlice,
            byte[] moreSlice,
            List<ChangedSlot> slots,
            List<ChangedSlot> afterMoreSlots,
            List<FieldCandidate> fieldCandidates
    ) {
        StringBuilder json = new StringBuilder(16_384);
        json.append("{\n");
        field(json, "beforeSave", quote(inputs.beforeSave().toString()), true, true);
        field(json, "afterSave", quote(inputs.afterSave().toString()), true, true);
        field(json, "moreSave", quote(inputs.moreSave().toString()), true, true);
        field(json, "anchoredOffset", Integer.toString(anchored.offset()), true, true);
        field(json, "anchoredLength", Integer.toString(anchored.length()), true, true);
        field(json, "resolvedMoreOffset", Integer.toString(moreOffset), true, true);
        field(json, "beforeHex", quote(hex(beforeSlice)), true, true);
        field(json, "afterHex", quote(hex(afterSlice)), true, true);
        field(json, "moreHex", quote(hex(moreSlice)), true, true);
        field(json, "beforeAscii", quote(ascii(beforeSlice)), true, true);
        field(json, "afterAscii", quote(ascii(afterSlice)), true, true);
        field(json, "moreAscii", quote(ascii(moreSlice)), true, true);

        json.append("  \"fieldCandidates\": [\n");
        for (int i = 0; i < fieldCandidates.size(); i++) {
            FieldCandidate candidate = fieldCandidates.get(i);
            json.append("    {\n");
            field(json, "name", quote(candidate.name()), false, true);
            field(json, "from", Integer.toString(candidate.from()), false, true);
            field(json, "to", Integer.toString(candidate.to()), false, true);
            intListField(json, "exactRelativeOffsets", candidate.exactRelativeOffsets(), true);
            intListField(json, "fromMatchedRelativeOffsets", candidate.fromMatchedRelativeOffsets(), true);
            field(json, "confidence", quote(candidate.confidence()), false, false);
            json.append("    }");
            if (i + 1 < fieldCandidates.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ],\n");

        json.append("  \"afterMoreChangedSlots\": [\n");
        for (int i = 0; i < afterMoreSlots.size(); i++) {
            appendSlot(json, afterMoreSlots.get(i), i + 1 < afterMoreSlots.size());
        }
        json.append("  ],\n");

        json.append("  \"changedSlots\": [\n");
        int rendered = Math.min(slots.size(), MAX_RENDERED_SLOTS);
        for (int i = 0; i < rendered; i++) {
            appendSlot(json, slots.get(i), i + 1 < rendered);
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private static void appendSlot(StringBuilder json, ChangedSlot slot, boolean trailingComma) {
        json.append("    {\n");
        field(json, "relativeOffset", Integer.toString(slot.relativeOffset()), false, true);
        field(json, "absoluteOffset", Integer.toString(slot.absoluteOffset()), false, true);
        field(json, "moreAbsoluteOffset", Integer.toString(slot.moreAbsoluteOffset()), false, true);
        field(json, "before", Integer.toString(slot.beforeValue()), false, true);
        field(json, "after", Integer.toString(slot.afterValue()), false, true);
        field(json, "more", Integer.toString(slot.moreValue()), false, true);
        listField(json, "confirmedBeforeAfter", slot.confirmedBeforeAfter(), true);
        listField(json, "confirmedAfterMore", slot.confirmedAfterMore(), true);
        listField(json, "tentativeAfterMore", slot.tentativeAfterMore(), true);
        field(json, "confidence", quote(slot.confidence()), false, false);
        json.append("    }");
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void listField(StringBuilder json, String name, List<String> values, boolean trailingComma) {
        json.append("      ").append(quote(name)).append(": [");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(", ");
            }
            json.append(quote(values.get(i)));
        }
        json.append("]");
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void intListField(StringBuilder json, String name, List<Integer> values, boolean trailingComma) {
        json.append("      ").append(quote(name)).append(": [");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(", ");
            }
            json.append(values.get(i));
        }
        json.append("]");
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void field(StringBuilder json, String name, String value, boolean topLevel, boolean trailingComma) {
        json.append(topLevel ? "  " : "      ")
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
        StringBuilder builder = new StringBuilder(bytes.length);
        for (byte value : bytes) {
            int unsigned = value & 0xFF;
            builder.append(unsigned >= 32 && unsigned <= 126 ? (char) unsigned : '.');
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

    private record Inputs(Path beforeSave, Path afterSave, Path moreSave, Path beforeAfterCsv, Path afterMoreCsv) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 5) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]), Path.of(args[3]), Path.of(args[4]));
            }
            if (args.length == 0) {
                return new Inputs(
                        Path.of("games/Feyenoord_before.fm"),
                        Path.of("games/Feyenoord_after.fm"),
                        Path.of("games/Feyenoord_more_after.fm"),
                        Path.of("gernot_trauner_changes.csv"),
                        Path.of("after_more_after.csv")
                );
            }
            throw new IllegalArgumentException(
                    "Usage: TraunerProfileBlockExtractor <before.fm> <after.fm> <more_after.fm> <before_after.csv> <after_more.csv>"
            );
        }
    }

    private record PlayerChange(String name, int from, int to) {
    }

    private record DiffRegion(int offset, int end) {
        private int length() {
            return end - offset;
        }
    }

    private static final class ChangedSlotBuilder {
        private final int relativeOffset;
        private final int absoluteOffset;
        private final int moreAbsoluteOffset;
        private final int beforeValue;
        private final int afterValue;
        private final int moreValue;
        private final List<String> confirmedBeforeAfter = new ArrayList<>();
        private final List<String> confirmedAfterMore = new ArrayList<>();
        private final List<String> tentativeAfterMore = new ArrayList<>();

        private ChangedSlotBuilder(int relativeOffset, int absoluteOffset, int moreAbsoluteOffset, int beforeValue, int afterValue, int moreValue) {
            this.relativeOffset = relativeOffset;
            this.absoluteOffset = absoluteOffset;
            this.moreAbsoluteOffset = moreAbsoluteOffset;
            this.beforeValue = beforeValue;
            this.afterValue = afterValue;
            this.moreValue = moreValue;
        }
    }

    private record ChangedSlot(
            int relativeOffset,
            int absoluteOffset,
            int moreAbsoluteOffset,
            int beforeValue,
            int afterValue,
            int moreValue,
            List<String> confirmedBeforeAfter,
            List<String> confirmedAfterMore,
            List<String> tentativeAfterMore,
            String confidence
    ) {
    }

    private record FieldCandidate(
            String name,
            int from,
            int to,
            List<Integer> exactRelativeOffsets,
            List<Integer> fromMatchedRelativeOffsets,
            String confidence
    ) {
    }
}
