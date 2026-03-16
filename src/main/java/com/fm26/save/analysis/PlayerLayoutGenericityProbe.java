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

public final class PlayerLayoutGenericityProbe {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int DUP_PAIR_DISTANCE = 4;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;

    private static final int PERSON_TO_TECHNICAL_PREFIX = 1_147;
    private static final int PERSON_TO_VISIBLE = 1_145;
    private static final int PERSON_TO_HIDDEN = 236;
    private static final int PERSON_TO_CONTRACT = 381;
    private static final int PERSON_TO_GENERAL = 1_192;
    private static final int PERSON_TO_POSITIONS = 1_160;

    private static final int TECHNICAL_PREFIX_LENGTH = 83;
    private static final int VISIBLE_LENGTH = 81;
    private static final int HIDDEN_LENGTH = 96;
    private static final int CONTRACT_LENGTH = 72;
    private static final int GENERAL_LENGTH = 16;
    private static final int POSITION_LENGTH = 13;

    private static final Map<String, ExpectedChange> EXPECTED = Map.of(
            "finishing", new ExpectedChange("visible", 0, 1, "times_five"),
            "pace", new ExpectedChange("visible", 36, 1, "times_five"),
            "concentration", new ExpectedChange("visible", 51, 1, "times_five"),
            "controversy", new ExpectedChange("hidden", 54, 1, "raw"),
            "potential_ability", new ExpectedChange("general", 8, 2, "u16_le"),
            "striker", new ExpectedChange("positions", 10, 1, "raw"),
            "contract_end", new ExpectedChange("contract", 8, 4, "day_year_u16"),
            "date_of_birth", new ExpectedChange("hidden", 26, 4, "day_year_u16")
    );

    private PlayerLayoutGenericityProbe() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] basePayload = loadPayload(inputs.baseSave());
        Integer basePersonPair = findPersonPair(basePayload, inputs.playerId());
        if (basePersonPair == null) {
            throw new IllegalStateException("Could not locate person pair for player " + Integer.toUnsignedString(inputs.playerId()));
        }

        List<ProbeResult> results = new ArrayList<>();
        for (Path save : inputs.targetSaves()) {
            byte[] targetPayload = loadPayload(save);
            List<Integer> targetPersonPairs = findPersonPairs(targetPayload, inputs.playerId());
            if (targetPersonPairs.isEmpty()) {
                results.add(new ProbeResult(save, List.of(), null, null, null, List.of(), "missing_person_pair"));
                continue;
            }
            String label = labelFromFileName(save.getFileName().toString());
            ExpectedChange expected = EXPECTED.get(label);
            if (expected == null) {
                results.add(new ProbeResult(save, targetPersonPairs, null, label, null, List.of(), "no_expected_mapping"));
                continue;
            }
            byte[] baseBlock = readBlock(basePayload, basePersonPair, expected.block());
            CandidateProbe best = null;
            for (int targetPersonPair : targetPersonPairs) {
                byte[] targetBlock = readBlock(targetPayload, targetPersonPair, expected.block());
                List<DiffSlot> diffs = diffSlots(baseBlock, targetBlock, blockAbsoluteOffset(targetPersonPair, expected.block()));
                boolean matched = diffs.stream().anyMatch(diff ->
                        diff.relativeOffset() >= expected.relativeOffset()
                                && diff.relativeOffset() < expected.relativeOffset() + expected.width()
                );
                CandidateProbe probe = new CandidateProbe(targetPersonPair, diffs, matched);
                if (best == null
                        || probe.matchedExpected()
                        || probe.diffs().size() > best.diffs().size()) {
                    best = probe;
                    if (probe.matchedExpected()) {
                        break;
                    }
                }
            }
            results.add(new ProbeResult(
                    save,
                    targetPersonPairs,
                    best == null ? null : best.personPair(),
                    label,
                    expected,
                    best == null ? List.of() : best.diffs(),
                    best != null && best.matchedExpected() ? "matched_expected_offset" : "unexpected_offset"
            ));
        }

        System.out.print(renderJson(inputs, basePersonPair, results));
    }

    private static String labelFromFileName(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("small_") || !lower.endsWith("_only.fm")) {
            return lower;
        }
        return lower.substring("small_".length(), lower.length() - "_only.fm".length());
    }

    private static Integer findPersonPair(byte[] payload, int playerId) {
        List<Integer> pairs = findPersonPairs(payload, playerId);
        return pairs.isEmpty() ? null : pairs.get(0);
    }

    private static List<Integer> findPersonPairs(byte[] payload, int playerId) {
        List<Integer> pairs = new ArrayList<>();
        byte b0 = (byte) (playerId & 0xFF);
        byte b1 = (byte) ((playerId >>> 8) & 0xFF);
        byte b2 = (byte) ((playerId >>> 16) & 0xFF);
        byte b3 = (byte) ((playerId >>> 24) & 0xFF);
        for (int offset = 0; offset + 8 <= payload.length; offset++) {
            if (offset >= PERSON_BLOCK_MAX_OFFSET) {
                break;
            }
            if (payload[offset] == b0
                    && payload[offset + 1] == b1
                    && payload[offset + 2] == b2
                    && payload[offset + 3] == b3
                    && payload[offset + 4] == b0
                    && payload[offset + 5] == b1
                    && payload[offset + 6] == b2
                    && payload[offset + 7] == b3) {
                pairs.add(offset);
            }
        }
        return pairs;
    }

    private static byte[] readBlock(byte[] payload, int personPair, String block) {
        int start = blockAbsoluteOffset(personPair, block);
        int length = switch (block) {
            case "technical_prefix" -> TECHNICAL_PREFIX_LENGTH;
            case "visible" -> VISIBLE_LENGTH;
            case "hidden" -> HIDDEN_LENGTH;
            case "contract" -> CONTRACT_LENGTH;
            case "general" -> GENERAL_LENGTH;
            case "positions" -> POSITION_LENGTH;
            default -> throw new IllegalArgumentException("Unknown block " + block);
        };
        byte[] out = new byte[length];
        System.arraycopy(payload, start, out, 0, length);
        return out;
    }

    private static int blockAbsoluteOffset(int personPair, String block) {
        return switch (block) {
            case "technical_prefix" -> personPair - PERSON_TO_TECHNICAL_PREFIX;
            case "visible" -> personPair - PERSON_TO_VISIBLE;
            case "hidden" -> personPair - PERSON_TO_HIDDEN;
            case "contract" -> personPair - PERSON_TO_CONTRACT;
            case "general" -> personPair - PERSON_TO_GENERAL;
            case "positions" -> personPair - PERSON_TO_POSITIONS;
            default -> throw new IllegalArgumentException("Unknown block " + block);
        };
    }

    private static List<DiffSlot> diffSlots(byte[] baseBlock, byte[] targetBlock, int absoluteBlockOffset) {
        List<DiffSlot> diffs = new ArrayList<>();
        for (int i = 0; i < Math.min(baseBlock.length, targetBlock.length); i++) {
            int before = baseBlock[i] & 0xFF;
            int after = targetBlock[i] & 0xFF;
            if (before != after) {
                diffs.add(new DiffSlot(i, absoluteBlockOffset + i, before, after));
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

    private static String renderJson(Inputs inputs, int basePersonPair, List<ProbeResult> results) {
        StringBuilder json = new StringBuilder(24_000);
        json.append("{\n");
        field(json, "baseSave", quote(inputs.baseSave().toString()), true);
        field(json, "playerId", Integer.toUnsignedString(inputs.playerId()), true);
        field(json, "basePersonPair", Integer.toString(basePersonPair), true);
        json.append("  \"results\": [\n");
        for (int i = 0; i < results.size(); i++) {
            ProbeResult result = results.get(i);
            json.append("    {\n");
            nested(json, "save", quote(result.save().toString()), true);
            nested(json, "label", quote(result.label() == null ? "" : result.label()), true);
            nested(json, "personPairCandidates", intList(result.personPairCandidates()), true);
            nested(json, "chosenPersonPair", result.personPair() == null ? "null" : Integer.toString(result.personPair()), true);
            if (result.expected() == null) {
                nested(json, "expectedBlock", "null", true);
                nested(json, "expectedOffset", "null", true);
            } else {
                nested(json, "expectedBlock", quote(result.expected().block()), true);
                nested(json, "expectedOffset", Integer.toString(result.expected().relativeOffset()), true);
            }
            nested(json, "status", quote(result.status()), true);
            json.append("      \"diffs\": [\n");
            for (int j = 0; j < result.diffs().size(); j++) {
                DiffSlot diff = result.diffs().get(j);
                json.append("        {")
                        .append("\"relativeOffset\": ").append(diff.relativeOffset()).append(", ")
                        .append("\"absoluteOffset\": ").append(diff.absoluteOffset()).append(", ")
                        .append("\"before\": ").append(diff.before()).append(", ")
                        .append("\"after\": ").append(diff.after()).append("}");
                if (j + 1 < result.diffs().size()) {
                    json.append(',');
                }
                json.append('\n');
            }
            json.append("      ]\n");
            json.append("    }");
            if (i + 1 < results.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private static void field(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("  ").append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void nested(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("      ").append(quote(name)).append(": ").append(value);
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

    private static String intList(List<Integer> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(values.get(i));
        }
        return out.append(']').toString();
    }

    private record Inputs(Path baseSave, int playerId, List<Path> targetSaves) {
        private static Inputs fromArgs(String[] args) {
            if (args.length > 0) {
                throw new IllegalArgumentException("Usage: PlayerLayoutGenericityProbe");
            }
            return new Inputs(
                    Path.of("games/Feyenoord_after.fm"),
                    37_060_899,
                    List.of(
                            Path.of("games/Small_finishing_only.fm"),
                            Path.of("games/Small_pace_only.fm"),
                            Path.of("games/Small_concentration_only.fm"),
                            Path.of("games/Small_controversy_only.fm"),
                            Path.of("games/Small_potential_ability_only.fm"),
                            Path.of("games/Small_striker_only.fm"),
                            Path.of("games/Small_contract_end_only.fm"),
                            Path.of("games/Small_date_of_birth_only.fm")
                    )
            );
        }
    }

    private record ExpectedChange(String block, int relativeOffset, int width, String encoding) {
    }

    private record ProbeResult(
            Path save,
            List<Integer> personPairCandidates,
            Integer personPair,
            String label,
            ExpectedChange expected,
            List<DiffSlot> diffs,
            String status
    ) {
    }

    private record DiffSlot(int relativeOffset, int absoluteOffset, int before, int after) {
    }

    private record CandidateProbe(int personPair, List<DiffSlot> diffs, boolean matchedExpected) {
    }
}
