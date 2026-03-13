package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class PlayerTailExtractor {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final byte[] ZSTD_MAGIC = new byte[]{0x28, (byte) 0xB5, 0x2F, (byte) 0xFD};
    private static final byte[] TAD_MAGIC = new byte[]{0x03, 0x01, 0x74, 0x61, 0x64, 0x2E};
    private static final int WINDOW_SIZE = 160;
    private static final int WINDOW_STEP = 16;
    private static final int CANDIDATE_CONTEXT = 48;
    private static final int MAX_CANDIDATES = 12;
    private static final int MAX_FRAME_HITS_TO_PROBE = 32;
    private static final int MAX_VALID_FRAMES = 8;
    private static final int MAX_FRAME_OUTPUT = 16 * 1024 * 1024;

    private PlayerTailExtractor() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] base = loadPayload(inputs.baseSave());
        byte[] more = loadPayload(inputs.moreSave());
        List<PlayerChange> changes = loadChanges(inputs.changesCsv());

        int overlap = Math.min(base.length, more.length);
        List<ByteDiff> overlapDiffs = computeOverlapDiffs(base, more, overlap);
        List<DiffRegion> diffRegions = buildDiffRegions(base, more, overlapDiffs);
        byte[] tail = slice(more, base.length, more.length);
        List<CandidateWindow> candidates = findTailCandidates(tail, base.length, changes);

        List<EmbeddedFrame> baseFrames = discoverFrames(inputs.baseSave());
        List<EmbeddedFrame> moreFrames = discoverFrames(inputs.moreSave());
        List<FrameDiffSummary> frameDiffs = compareFrames(baseFrames, moreFrames);
        List<NameAnchor> anchors = discoverNameAnchors(more, List.of("Gernot", "Trauner", "Feyenoord"));
        List<ValueRecord> valueRecords = findStructuredValueRecords(more, Set.of(1, 5, 9, 12, 14, 19, 20, 150));

        System.out.println(renderJson(
                inputs,
                changes,
                base.length,
                more.length,
                overlapDiffs,
                diffRegions,
                candidates,
                baseFrames,
                moreFrames,
                frameDiffs,
                anchors,
                valueRecords
        ));
    }

    private static byte[] loadPayload(Path path) throws IOException {
        if (!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".fm")) {
            return Files.readAllBytes(path);
        }
        try (InputStream raw = new BufferedInputStream(Files.newInputStream(path));
             InputStream skipped = skipFully(raw, FMF_ZSTD_OFFSET);
             ZstdInputStream zstd = new ZstdInputStream(skipped)) {
            return readZstdStream(zstd, Integer.MAX_VALUE);
        }
    }

    private static List<EmbeddedFrame> discoverFrames(Path save) throws IOException {
        if (!save.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".fm")) {
            return List.of();
        }

        byte[] bytes = Files.readAllBytes(save);
        List<Integer> offsets = findAll(bytes, ZSTD_MAGIC, MAX_FRAME_HITS_TO_PROBE);
        List<EmbeddedFrame> frames = new ArrayList<>();
        for (int offset : offsets) {
            byte[] payload = tryReadEmbeddedFrame(bytes, offset);
            if (payload == null || payload.length < TAD_MAGIC.length || !startsWith(payload, TAD_MAGIC)) {
                continue;
            }
            frames.add(new EmbeddedFrame(
                    save.toString(),
                    offset,
                    payload.length,
                    previewAscii(slice(payload, 0, Math.min(payload.length, 96))),
                    asciiRatio(slice(payload, 0, Math.min(payload.length, 4096)))
            ));
            if (frames.size() >= MAX_VALID_FRAMES) {
                break;
            }
        }
        return frames;
    }

    private static byte[] tryReadEmbeddedFrame(byte[] file, int offset) {
        try (InputStream raw = new ByteArrayInputStream(file, offset, file.length - offset);
             ZstdInputStream zstd = new ZstdInputStream(raw)) {
            return readZstdStream(zstd, MAX_FRAME_OUTPUT);
        } catch (IOException ignored) {
            return null;
        }
    }

    private static byte[] readZstdStream(ZstdInputStream zstd, int maxBytes) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        while (output.size() < maxBytes) {
            try {
                int maxRead = Math.min(buffer.length, maxBytes - output.size());
                int read = zstd.read(buffer, 0, maxRead);
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

    private static List<ByteDiff> computeOverlapDiffs(byte[] base, byte[] more, int overlap) {
        List<ByteDiff> diffs = new ArrayList<>();
        for (int i = 0; i < overlap; i++) {
            if (base[i] != more[i]) {
                diffs.add(new ByteDiff(i, base[i] & 0xFF, more[i] & 0xFF));
            }
        }
        return diffs;
    }

    private static List<CandidateWindow> findTailCandidates(byte[] tail, int absoluteBaseOffset, List<PlayerChange> changes) {
        List<CandidateWindow> raw = new ArrayList<>();
        for (int offset = 0; offset + WINDOW_SIZE <= tail.length; offset += WINDOW_STEP) {
            byte[] window = slice(tail, offset, offset + WINDOW_SIZE);
            double asciiRatio = asciiRatio(window);
            WindowProfile profile = profile(window);
            if (asciiRatio > 0.58 || profile.maxPrintableRun() > 14) {
                continue;
            }

            List<String> matched = new ArrayList<>();
            int directByteHits = 0;
            for (PlayerChange change : changes) {
                boolean hit = false;
                if (change.to() >= 0 && change.to() < 256 && contains(window, (byte) change.to())) {
                    directByteHits++;
                    hit = true;
                }
                if (contains(window, toLe16(change.to()))) {
                    hit = true;
                }
                if (hit) {
                    matched.add(change.name());
                }
            }
            if (matched.size() < 3) {
                continue;
            }

            int score = matched.size() * 10 + directByteHits * 3 - (int) Math.round(asciiRatio * 10) - profile.longPrintableRuns() * 4;
            raw.add(new CandidateWindow(
                    offset,
                    absoluteBaseOffset + offset,
                    score,
                    asciiRatio,
                    matched,
                    previewHex(slice(tail, Math.max(0, offset - CANDIDATE_CONTEXT), Math.min(tail.length, offset + WINDOW_SIZE + CANDIDATE_CONTEXT))),
                    previewAscii(slice(tail, Math.max(0, offset - CANDIDATE_CONTEXT), Math.min(tail.length, offset + WINDOW_SIZE + CANDIDATE_CONTEXT))),
                    sampleU16(window)
            ));
        }

        List<CandidateWindow> merged = new ArrayList<>();
        raw.sort(Comparator.comparingInt(CandidateWindow::tailOffset));
        for (CandidateWindow candidate : raw) {
            if (merged.isEmpty()) {
                merged.add(candidate);
                continue;
            }
            CandidateWindow previous = merged.getLast();
            if (candidate.tailOffset() - previous.tailOffset() < WINDOW_SIZE) {
                if (candidate.score() > previous.score()) {
                    merged.set(merged.size() - 1, candidate);
                }
            } else {
                merged.add(candidate);
            }
        }

        merged.sort(Comparator
                .comparingInt(CandidateWindow::score).reversed()
                .thenComparingDouble(CandidateWindow::asciiRatio)
                .thenComparingInt(CandidateWindow::tailOffset));
        return merged.size() > MAX_CANDIDATES ? merged.subList(0, MAX_CANDIDATES) : merged;
    }

    private static List<DiffRegion> buildDiffRegions(byte[] base, byte[] more, List<ByteDiff> overlapDiffs) {
        if (overlapDiffs.isEmpty()) {
            return List.of();
        }
        List<DiffRegion> regions = new ArrayList<>();
        int start = overlapDiffs.getFirst().offset();
        int end = start + 1;
        for (int i = 1; i < overlapDiffs.size(); i++) {
            int current = overlapDiffs.get(i).offset();
            if (current - end <= 32) {
                end = current + 1;
                continue;
            }
            regions.add(diffRegion(base, more, start, end));
            start = current;
            end = current + 1;
        }
        regions.add(diffRegion(base, more, start, end));
        regions.sort(Comparator.comparingInt(DiffRegion::length).reversed().thenComparingInt(DiffRegion::offset));
        return regions.size() > 16 ? regions.subList(0, 16) : regions;
    }

    private static DiffRegion diffRegion(byte[] base, byte[] more, int start, int end) {
        int from = Math.max(0, start - 24);
        int to = Math.min(Math.min(base.length, more.length), end + 48);
        return new DiffRegion(
                start,
                end - start,
                previewHex(slice(base, from, to)),
                previewHex(slice(more, from, to)),
                previewAscii(slice(base, from, to)),
                previewAscii(slice(more, from, to))
        );
    }

    private static List<FrameDiffSummary> compareFrames(List<EmbeddedFrame> baseFrames, List<EmbeddedFrame> moreFrames) throws IOException {
        List<FrameDiffSummary> summaries = new ArrayList<>();
        int count = Math.min(baseFrames.size(), moreFrames.size());
        for (int i = 0; i < count; i++) {
            EmbeddedFrame baseFrame = baseFrames.get(i);
            EmbeddedFrame moreFrame = moreFrames.get(i);
            byte[] basePayload = tryReadEmbeddedFrame(Files.readAllBytes(Path.of(baseFrame.sourcePath())), baseFrame.offset());
            byte[] morePayload = tryReadEmbeddedFrame(Files.readAllBytes(Path.of(moreFrame.sourcePath())), moreFrame.offset());
            if (basePayload == null || morePayload == null) {
                continue;
            }

            int overlap = Math.min(basePayload.length, morePayload.length);
            List<Integer> diffOffsets = new ArrayList<>();
            for (int offset = 0; offset < overlap && diffOffsets.size() < 12; offset++) {
                if (basePayload[offset] != morePayload[offset]) {
                    diffOffsets.add(offset);
                }
            }
            int diffCount = 0;
            for (int offset = 0; offset < overlap; offset++) {
                if (basePayload[offset] != morePayload[offset]) {
                    diffCount++;
                }
            }
            diffCount += Math.abs(basePayload.length - morePayload.length);

            summaries.add(new FrameDiffSummary(
                    i,
                    baseFrame.offset(),
                    moreFrame.offset(),
                    basePayload.length,
                    morePayload.length,
                    diffCount,
                    diffOffsets,
                    diffOffsets.isEmpty() ? "" : previewHex(diffContext(basePayload, morePayload, diffOffsets.getFirst()))
            ));
        }
        return summaries;
    }

    private static byte[] diffContext(byte[] basePayload, byte[] morePayload, int offset) {
        int from = Math.max(0, offset - 24);
        int to = Math.min(Math.min(basePayload.length, morePayload.length), offset + 40);
        byte[] merged = new byte[(to - from) * 2];
        int cursor = 0;
        for (int i = from; i < to; i++) {
            merged[cursor++] = basePayload[i];
        }
        for (int i = from; i < to; i++) {
            merged[cursor++] = morePayload[i];
        }
        return merged;
    }

    private static List<NameAnchor> discoverNameAnchors(byte[] payload, List<String> names) {
        List<NameAnchor> anchors = new ArrayList<>();
        Set<Integer> seenOffsets = new LinkedHashSet<>();
        for (String name : names) {
            byte[] needle = name.getBytes(StandardCharsets.UTF_8);
            int index = 0;
            while (true) {
                index = indexOf(payload, needle, index);
                if (index < 0) {
                    break;
                }
                if (seenOffsets.add(index)) {
                    int idOffset = index + needle.length;
                    int id = idOffset + 4 <= payload.length ? le32(payload, idOffset) : -1;
                    int declaredLength = idOffset + 8 <= payload.length ? le32(payload, idOffset + 4) : -1;
                    anchors.add(new NameAnchor(name, index, id, declaredLength));
                }
                index++;
            }
        }
        anchors.sort(Comparator.comparing(NameAnchor::name).thenComparingInt(NameAnchor::offset));
        return anchors;
    }

    private static List<ValueRecord> findStructuredValueRecords(byte[] payload, Set<Integer> interestingValues) {
        List<ValueRecord> records = new ArrayList<>();
        for (int i = 0; i + 24 <= payload.length; i++) {
            if (payload[i] != 0x02 || payload[i + 10] != 0x01) {
                continue;
            }
            int value = payload[i + 1] & 0xFF;
            if (!interestingValues.contains(value)) {
                continue;
            }
            byte[] nextEight = slice(payload, i + 2, i + 10);
            if (nextEight[1] != 0x00 || nextEight[3] != 0x00 || nextEight[5] != 0x00 || nextEight[7] != 0x00) {
                continue;
            }
            records.add(new ValueRecord(
                    i,
                    value,
                    previewHex(slice(payload, i, i + 24)),
                    previewAscii(slice(payload, Math.max(0, i - 24), Math.min(payload.length, i + 48)))
            ));
            if (records.size() >= 24) {
                break;
            }
        }
        return records;
    }

    private static List<Integer> findAll(byte[] haystack, byte[] needle, int limit) {
        List<Integer> hits = new ArrayList<>();
        int index = 0;
        while (index <= haystack.length - needle.length && hits.size() < limit) {
            int found = indexOf(haystack, needle, index);
            if (found < 0) {
                break;
            }
            hits.add(found);
            index = found + 1;
        }
        return hits;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        for (int i = Math.max(0, from); i <= haystack.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (bytes[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static int le32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF)
                | ((bytes[offset + 1] & 0xFF) << 8)
                | ((bytes[offset + 2] & 0xFF) << 16)
                | ((bytes[offset + 3] & 0xFF) << 24);
    }

    private static byte[] toLe16(int value) {
        return new byte[]{(byte) (value & 0xFF), (byte) ((value >>> 8) & 0xFF)};
    }

    private static boolean contains(byte[] bytes, byte value) {
        for (byte current : bytes) {
            if (current == value) {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(byte[] bytes, byte[] pattern) {
        if (bytes.length < pattern.length) {
            return false;
        }
        for (int i = 0; i <= bytes.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (bytes[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    private static double asciiRatio(byte[] bytes) {
        int ascii = 0;
        for (byte value : bytes) {
            int unsigned = value & 0xFF;
            if (unsigned >= 32 && unsigned <= 126) {
                ascii++;
            }
        }
        return bytes.length == 0 ? 0.0 : (double) ascii / bytes.length;
    }

    private static WindowProfile profile(byte[] bytes) {
        int currentRun = 0;
        int maxRun = 0;
        int longRuns = 0;
        for (byte value : bytes) {
            int unsigned = value & 0xFF;
            if (unsigned >= 32 && unsigned <= 126) {
                currentRun++;
            } else if (currentRun > 0) {
                maxRun = Math.max(maxRun, currentRun);
                if (currentRun >= 5) {
                    longRuns++;
                }
                currentRun = 0;
            }
        }
        if (currentRun > 0) {
            maxRun = Math.max(maxRun, currentRun);
            if (currentRun >= 5) {
                longRuns++;
            }
        }
        return new WindowProfile(longRuns, maxRun);
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

    private static String previewHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                builder.append(' ');
            }
            builder.append(String.format(Locale.ROOT, "%02x", bytes[i] & 0xFF));
        }
        return builder.toString();
    }

    private static String previewAscii(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length);
        for (byte value : bytes) {
            int unsigned = value & 0xFF;
            if (unsigned >= 32 && unsigned <= 126) {
                builder.append((char) unsigned);
            } else {
                builder.append('.');
            }
        }
        return builder.toString();
    }

    private static List<Integer> sampleU16(byte[] bytes) {
        List<Integer> values = new ArrayList<>();
        for (int i = 0; i + 1 < bytes.length && values.size() < 24; i += 2) {
            values.add((bytes[i] & 0xFF) | ((bytes[i + 1] & 0xFF) << 8));
        }
        return values;
    }

    private static String renderJson(
            Inputs inputs,
            List<PlayerChange> knownChanges,
            int baseLength,
            int moreLength,
            List<ByteDiff> overlapDiffs,
            List<DiffRegion> diffRegions,
            List<CandidateWindow> candidates,
            List<EmbeddedFrame> baseFrames,
            List<EmbeddedFrame> moreFrames,
            List<FrameDiffSummary> frameDiffs,
            List<NameAnchor> anchors,
            List<ValueRecord> valueRecords
    ) {
        StringBuilder json = new StringBuilder(24_576);
        json.append("{\n");
        appendField(json, "playerId", Integer.toString(inputs.playerId()), true, true);
        appendField(json, "baseSave", quote(inputs.baseSave().toString()), true, true);
        appendField(json, "moreSave", quote(inputs.moreSave().toString()), true, true);
        appendField(json, "changesCsv", quote(inputs.changesCsv().toString()), true, true);
        appendField(json, "basePayloadSize", Integer.toString(baseLength), true, true);
        appendField(json, "morePayloadSize", Integer.toString(moreLength), true, true);
        appendField(json, "appendedTailSize", Integer.toString(moreLength - baseLength), true, true);
        appendField(
                json,
                "notes",
                quote("embeddedFrames are auto-discovered Zstd substreams; valueRecords are heuristic fixed-width matches"),
                true,
                true
        );

        json.append("  \"bestEffortProfile\": {\n");
        appendField(json, "playerId", Integer.toString(inputs.playerId()), false, true);
        appendField(json, "confidence", quote(candidates.isEmpty() ? "low" : "tentative"), false, true);
        appendField(
                json,
                "summary",
                quote(candidates.isEmpty()
                        ? "CSV values are confirmed; frame diffs and name ids are now surfaced, but the player-owned binary record is not isolated yet"
                        : "CSV values are confirmed and tail candidates were found, but record ownership is still tentative"),
                false,
                true
        );
        json.append("      \"attributes\": {\n");
        for (int i = 0; i < knownChanges.size(); i++) {
            PlayerChange change = knownChanges.get(i);
            json.append("        ")
                    .append(quote(change.name()))
                    .append(": {\"before\": ").append(change.from())
                    .append(", \"after\": ").append(change.to())
                    .append("}");
            if (i + 1 < knownChanges.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("      }\n");
        json.append("  },\n");

        json.append("  \"embeddedFrames\": {\n");
        json.append("    \"base\": [\n");
        appendFrames(json, baseFrames);
        json.append("    ],\n");
        json.append("    \"more\": [\n");
        appendFrames(json, moreFrames);
        json.append("    ]\n");
        json.append("  },\n");

        json.append("  \"frameDiffs\": [\n");
        for (int i = 0; i < frameDiffs.size(); i++) {
            FrameDiffSummary summary = frameDiffs.get(i);
            json.append("    {\n");
            appendField(json, "frameIndex", Integer.toString(summary.frameIndex()), false, true);
            appendField(json, "baseOffset", Integer.toString(summary.baseOffset()), false, true);
            appendField(json, "moreOffset", Integer.toString(summary.moreOffset()), false, true);
            appendField(json, "baseSize", Integer.toString(summary.baseSize()), false, true);
            appendField(json, "moreSize", Integer.toString(summary.moreSize()), false, true);
            appendField(json, "diffCount", Integer.toString(summary.diffCount()), false, true);
            json.append("      \"sampleDiffOffsets\": [");
            for (int j = 0; j < summary.sampleDiffOffsets().size(); j++) {
                if (j > 0) {
                    json.append(", ");
                }
                json.append(summary.sampleDiffOffsets().get(j));
            }
            json.append("],\n");
            appendField(json, "diffContext", quote(summary.diffContext()), false, false);
            json.append("    }");
            if (i + 1 < frameDiffs.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ],\n");

        json.append("  \"nameAnchors\": [\n");
        for (int i = 0; i < anchors.size(); i++) {
            NameAnchor anchor = anchors.get(i);
            json.append("    {")
                    .append("\"name\": ").append(quote(anchor.name())).append(", ")
                    .append("\"offset\": ").append(anchor.offset()).append(", ")
                    .append("\"candidateId\": ").append(anchor.candidateId()).append(", ")
                    .append("\"declaredLength\": ").append(anchor.declaredLength())
                    .append("}");
            if (i + 1 < anchors.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ],\n");

        json.append("  \"overlapDiffs\": [\n");
        for (int i = 0; i < overlapDiffs.size(); i++) {
            ByteDiff diff = overlapDiffs.get(i);
            json.append("    {")
                    .append("\"offset\": ").append(diff.offset()).append(", ")
                    .append("\"before\": ").append(diff.beforeValue()).append(", ")
                    .append("\"after\": ").append(diff.afterValue())
                    .append("}");
            if (i + 1 < overlapDiffs.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ],\n");

        json.append("  \"diffRegions\": [\n");
        for (int i = 0; i < diffRegions.size(); i++) {
            DiffRegion region = diffRegions.get(i);
            json.append("    {\n");
            appendField(json, "offset", Integer.toString(region.offset()), false, true);
            appendField(json, "length", Integer.toString(region.length()), false, true);
            appendField(json, "beforeHex", quote(region.beforeHex()), false, true);
            appendField(json, "afterHex", quote(region.afterHex()), false, true);
            appendField(json, "beforeAscii", quote(region.beforeAscii()), false, true);
            appendField(json, "afterAscii", quote(region.afterAscii()), false, false);
            json.append("    }");
            if (i + 1 < diffRegions.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ],\n");

        json.append("  \"valueRecords\": [\n");
        for (int i = 0; i < valueRecords.size(); i++) {
            ValueRecord record = valueRecords.get(i);
            json.append("    {")
                    .append("\"offset\": ").append(record.offset()).append(", ")
                    .append("\"value\": ").append(record.value()).append(", ")
                    .append("\"hex\": ").append(quote(record.hex())).append(", ")
                    .append("\"ascii\": ").append(quote(record.ascii()))
                    .append("}");
            if (i + 1 < valueRecords.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ],\n");

        json.append("  \"tailCandidates\": [\n");
        for (int i = 0; i < candidates.size(); i++) {
            CandidateWindow candidate = candidates.get(i);
            json.append("    {\n");
            appendField(json, "tailOffset", Integer.toString(candidate.tailOffset()), false, true);
            appendField(json, "absoluteOffset", Integer.toString(candidate.absoluteOffset()), false, true);
            appendField(json, "score", Integer.toString(candidate.score()), false, true);
            appendField(json, "asciiRatio", String.format(Locale.ROOT, "%.3f", candidate.asciiRatio()), false, true);

            json.append("      \"matchedChanges\": [");
            for (int j = 0; j < candidate.matchedChanges().size(); j++) {
                if (j > 0) {
                    json.append(", ");
                }
                json.append(quote(candidate.matchedChanges().get(j)));
            }
            json.append("],\n");

            json.append("      \"u16Sample\": [");
            for (int j = 0; j < candidate.u16Sample().size(); j++) {
                if (j > 0) {
                    json.append(", ");
                }
                json.append(candidate.u16Sample().get(j));
            }
            json.append("],\n");

            appendField(json, "hexPreview", quote(candidate.hexPreview()), false, true);
            appendField(json, "asciiPreview", quote(candidate.asciiPreview()), false, false);
            json.append("    }");
            if (i + 1 < candidates.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private static void appendFrames(StringBuilder json, List<EmbeddedFrame> frames) {
        for (int i = 0; i < frames.size(); i++) {
            EmbeddedFrame frame = frames.get(i);
            json.append("      {")
                    .append("\"offset\": ").append(frame.offset()).append(", ")
                    .append("\"size\": ").append(frame.size()).append(", ")
                    .append("\"asciiRatio\": ").append(String.format(Locale.ROOT, "%.3f", frame.asciiRatio())).append(", ")
                    .append("\"preview\": ").append(quote(frame.preview()))
                    .append("}");
            if (i + 1 < frames.size()) {
                json.append(',');
            }
            json.append('\n');
        }
    }

    private static void appendField(StringBuilder json, String name, String value, boolean topLevel, boolean trailingComma) {
        json.append(topLevel ? "  " : "      ")
                .append(quote(name))
                .append(": ")
                .append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static String quote(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 8);
        escaped.append('"');
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            switch (current) {
                case '\\' -> escaped.append("\\\\");
                case '"' -> escaped.append("\\\"");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (current < 32) {
                        escaped.append(String.format(Locale.ROOT, "\\u%04x", (int) current));
                    } else {
                        escaped.append(current);
                    }
                }
            }
        }
        escaped.append('"');
        return escaped.toString();
    }

    private record Inputs(Path baseSave, Path moreSave, Path changesCsv, int playerId) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 4) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]), Integer.parseInt(args[3]));
            }
            if (args.length == 0) {
                return new Inputs(
                        Path.of("games/Feyenoord_after.fm"),
                        Path.of("games/Feyenoord_more_after.fm"),
                        Path.of("after_more_after.csv"),
                        16_023_929
                );
            }
            throw new IllegalArgumentException(
                    "Usage: PlayerTailExtractor <after.fm|bin> <more_after.fm|bin> <changes.csv> <playerId>"
            );
        }
    }

    private record PlayerChange(String name, int from, int to) {
    }

    private record ByteDiff(int offset, int beforeValue, int afterValue) {
    }

    private record CandidateWindow(
            int tailOffset,
            int absoluteOffset,
            int score,
            double asciiRatio,
            List<String> matchedChanges,
            String hexPreview,
            String asciiPreview,
            List<Integer> u16Sample
    ) {
    }

    private record WindowProfile(int longPrintableRuns, int maxPrintableRun) {
    }

    private record EmbeddedFrame(String sourcePath, int offset, int size, String preview, double asciiRatio) {
    }

    private record FrameDiffSummary(
            int frameIndex,
            int baseOffset,
            int moreOffset,
            int baseSize,
            int moreSize,
            int diffCount,
            List<Integer> sampleDiffOffsets,
            String diffContext
    ) {
    }

    private record NameAnchor(String name, int offset, int candidateId, int declaredLength) {
    }

    private record ValueRecord(int offset, int value, String hex, String ascii) {
    }

    private record DiffRegion(
            int offset,
            int length,
            String beforeHex,
            String afterHex,
            String beforeAscii,
            String afterAscii
    ) {
    }
}
