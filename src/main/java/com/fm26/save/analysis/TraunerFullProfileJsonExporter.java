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
import java.time.LocalDate;
import java.util.Map;
import java.util.List;
import java.util.Locale;

public final class TraunerFullProfileJsonExporter {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int TRAUNER_PLAYER_ID = 16_023_929;
    private static final int TRAUNER_CLUB_DATABASE_ID = 1_013;

    private static final BlockDefinition TECHNICAL_PREFIX_BLOCK = new BlockDefinition("technical_prefix", 66_582_078, 83, 250_000);
    private static final BlockDefinition VISIBLE_BLOCK = new BlockDefinition("visible", 66_582_080, 81, 250_000);
    private static final BlockDefinition HIDDEN_BLOCK = new BlockDefinition("hidden", 66_582_989, 96, 250_000);
    private static final BlockDefinition CONTRACT_BLOCK = new BlockDefinition("contract", 66_582_844, 72, 250_000);
    private static final BlockDefinition GENERAL_BLOCK = new BlockDefinition("general", 66_582_033, 16, 250_000);
    private static final BlockDefinition GOALKEEPER_BLOCK = new BlockDefinition("goalkeeper", 66_582_063, 1, 250_000);
    private static final BlockDefinition POSITION_BLOCK = new BlockDefinition("positions", 66_582_065, 13, 250_000);
    private static final int FIRST_NAME_ID_OFFSET = 7;
    private static final int LAST_NAME_ID_OFFSET = 12;
    private static final int FIRST_NAME_ENTRY_REFERENCE = 49_357_264;
    private static final int LAST_NAME_ENTRY_REFERENCE = 53_807_583;
    private static final int FIRST_NAME_TABLE_REFERENCE = 49_357_264;
    private static final int LAST_NAME_TABLE_REFERENCE = 53_807_583;
    private static final Map<Integer, String> NATIONALITY_NAMES = Map.of(
            129, "Austria",
            158, "Netherlands"
    );

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
            new FieldMapping("left foot", VISIBLE_BLOCK, 22, ValueEncoding.TIMES_FIVE),
            new FieldMapping("right foot", VISIBLE_BLOCK, 23, ValueEncoding.TIMES_FIVE),
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
            new FieldMapping("controversy", HIDDEN_BLOCK, 54, ValueEncoding.RAW),
            new FieldMapping("goalkeeper", GOALKEEPER_BLOCK, 0, ValueEncoding.RAW),
            new FieldMapping("defender left", POSITION_BLOCK, 0, ValueEncoding.RAW),
            new FieldMapping("defender central", POSITION_BLOCK, 1, ValueEncoding.RAW),
            new FieldMapping("defender right", POSITION_BLOCK, 2, ValueEncoding.RAW),
            new FieldMapping("defensive midfielder", POSITION_BLOCK, 3, ValueEncoding.RAW),
            new FieldMapping("midfielder left", POSITION_BLOCK, 4, ValueEncoding.RAW),
            new FieldMapping("midfielder central", POSITION_BLOCK, 5, ValueEncoding.RAW),
            new FieldMapping("midfielder right", POSITION_BLOCK, 6, ValueEncoding.RAW),
            new FieldMapping("attacking midfielder left", POSITION_BLOCK, 7, ValueEncoding.RAW),
            new FieldMapping("attacking midfielder central", POSITION_BLOCK, 8, ValueEncoding.RAW),
            new FieldMapping("attacking midfielder right", POSITION_BLOCK, 9, ValueEncoding.RAW),
            new FieldMapping("striker", POSITION_BLOCK, 10, ValueEncoding.RAW),
            new FieldMapping("wing back left", POSITION_BLOCK, 11, ValueEncoding.RAW),
            new FieldMapping("wing back right", POSITION_BLOCK, 12, ValueEncoding.RAW)
    );

    private static final List<WideFieldMapping> GENERAL_FIELD_MAPPINGS = List.of(
            new WideFieldMapping("home reputation", GENERAL_BLOCK, 0, WideValueEncoding.U16_LE),
            new WideFieldMapping("current reputation", GENERAL_BLOCK, 2, WideValueEncoding.U16_LE),
            new WideFieldMapping("world reputation", GENERAL_BLOCK, 4, WideValueEncoding.U16_LE),
            new WideFieldMapping("current ability", GENERAL_BLOCK, 6, WideValueEncoding.U16_LE),
            new WideFieldMapping("potential ability", GENERAL_BLOCK, 8, WideValueEncoding.U16_LE)
    );

    private static final List<WideFieldMapping> CONTRACT_FIELD_MAPPINGS = List.of(
            new WideFieldMapping("salary_gbp_per_week", CONTRACT_BLOCK, 63, WideValueEncoding.U32_LE)
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

        MatchWindow contractWindow = new MatchWindow(
                hiddenWindow.offset() - (HIDDEN_BLOCK.referenceOffset() - CONTRACT_BLOCK.referenceOffset()),
                CONTRACT_BLOCK.length(),
                CONTRACT_BLOCK.length()
        );
        byte[] contractTarget = slice(targetPayload, contractWindow.offset(), contractWindow.offset() + CONTRACT_BLOCK.length());

        byte[] generalReference = slice(referencePayload, GENERAL_BLOCK.referenceOffset(), GENERAL_BLOCK.referenceOffset() + GENERAL_BLOCK.length());
        MatchWindow generalWindow = locateBestWindow(targetPayload, generalReference, GENERAL_BLOCK.referenceOffset(), GENERAL_BLOCK.searchRadius());
        byte[] generalTarget = slice(targetPayload, generalWindow.offset(), generalWindow.offset() + GENERAL_BLOCK.length());

        MatchWindow positionWindow = new MatchWindow(
                visibleWindow.offset() - (VISIBLE_BLOCK.referenceOffset() - POSITION_BLOCK.referenceOffset()),
                POSITION_BLOCK.length(),
                POSITION_BLOCK.length()
        );
        byte[] positionTarget = slice(targetPayload, positionWindow.offset(), positionWindow.offset() + POSITION_BLOCK.length());
        MatchWindow goalkeeperWindow = new MatchWindow(
                visibleWindow.offset() - (VISIBLE_BLOCK.referenceOffset() - GOALKEEPER_BLOCK.referenceOffset()),
                GOALKEEPER_BLOCK.length(),
                GOALKEEPER_BLOCK.length()
        );
        byte[] goalkeeperTarget = slice(targetPayload, goalkeeperWindow.offset(), goalkeeperWindow.offset() + GOALKEEPER_BLOCK.length());
        ResolvedName resolvedName = resolveName(targetPayload, hiddenTarget);
        String resolvedClub = resolveClubName(targetPayload, TRAUNER_CLUB_DATABASE_ID);

        System.out.println(renderJson(
                inputs,
                referencePayload.length,
                targetPayload.length,
                resolvedName,
                resolvedClub,
                technicalPrefixWindow,
                technicalPrefixTarget,
                visibleWindow,
                visibleTarget,
                hiddenWindow,
                hiddenTarget,
                contractWindow,
                contractTarget,
                generalWindow,
                generalTarget,
                goalkeeperWindow,
                goalkeeperTarget,
                positionWindow,
                positionTarget
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
            ResolvedName resolvedName,
            String resolvedClub,
            MatchWindow technicalPrefixWindow,
            byte[] technicalPrefixTarget,
            MatchWindow visibleWindow,
            byte[] visibleTarget,
            MatchWindow hiddenWindow,
            byte[] hiddenTarget,
            MatchWindow contractWindow,
            byte[] contractTarget,
            MatchWindow generalWindow,
            byte[] generalTarget,
            MatchWindow goalkeeperWindow,
            byte[] goalkeeperTarget,
            MatchWindow positionWindow,
            byte[] positionTarget
    ) {
        StringBuilder json = new StringBuilder(8192);
        json.append("{\n");
        appendField(json, "playerId", Integer.toString(TRAUNER_PLAYER_ID), true);
        appendField(json, "name", quote(resolvedName.fullName()), true);
        appendField(json, "firstName", quote(resolvedName.firstName()), true);
        appendField(json, "lastName", quote(resolvedName.lastName()), true);
        appendField(json, "club", quote(resolvedClub), true);
        appendField(json, "referenceSave", quote(inputs.referenceSave().toString()), true);
        appendField(json, "targetSave", quote(inputs.targetSave().toString()), true);
        appendField(json, "referencePayloadSize", Integer.toString(referencePayloadSize), true);
        appendField(json, "targetPayloadSize", Integer.toString(targetPayloadSize), true);

        json.append("  \"blocks\": {\n");
        renderBlock(json, "technical_prefix", TECHNICAL_PREFIX_BLOCK, technicalPrefixWindow, technicalPrefixTarget, true);
        renderBlock(json, "visible", VISIBLE_BLOCK, visibleWindow, visibleTarget, true);
        renderBlock(json, "hidden", HIDDEN_BLOCK, hiddenWindow, hiddenTarget, true);
        renderBlock(json, "contract", CONTRACT_BLOCK, contractWindow, contractTarget, true);
        renderBlock(json, "general", GENERAL_BLOCK, generalWindow, generalTarget, true);
        renderBlock(json, "goalkeeper", GOALKEEPER_BLOCK, goalkeeperWindow, goalkeeperTarget, true);
        renderBlock(json, "positions", POSITION_BLOCK, positionWindow, positionTarget, false);
        json.append("  },\n");

        json.append("  \"attributes\": {\n");
        int totalFields = FIELD_MAPPINGS.size() + GENERAL_FIELD_MAPPINGS.size() + CONTRACT_FIELD_MAPPINGS.size() + 3;
        int emitted = 0;
        for (FieldMapping mapping : FIELD_MAPPINGS) {
            byte[] block;
            int blockOffset;
            if (mapping.block().name().equals(TECHNICAL_PREFIX_BLOCK.name())) {
                block = technicalPrefixTarget;
                blockOffset = technicalPrefixWindow.offset();
            } else if (mapping.block().name().equals(VISIBLE_BLOCK.name())) {
                block = visibleTarget;
                blockOffset = visibleWindow.offset();
            } else if (mapping.block().name().equals(GOALKEEPER_BLOCK.name())) {
                block = goalkeeperTarget;
                blockOffset = goalkeeperWindow.offset();
            } else if (mapping.block().name().equals(POSITION_BLOCK.name())) {
                block = positionTarget;
                blockOffset = positionWindow.offset();
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
            emitted++;
            if (emitted < totalFields) {
                json.append(',');
            }
            json.append('\n');
        }

        int contractEndDayOfYear = WideValueEncoding.U16_LE.decode(contractTarget, 8);
        int contractEndYear = WideValueEncoding.U16_LE.decode(contractTarget, 10);
        LocalDate contractEnd = decodeDayOfYear(contractEndYear, contractEndDayOfYear);
        int dateOfBirthDayOfYear = WideValueEncoding.U16_LE.decode(hiddenTarget, 26);
        int dateOfBirthYear = WideValueEncoding.U16_LE.decode(hiddenTarget, 28);
        LocalDate dateOfBirth = decodeDayOfYear(dateOfBirthYear, dateOfBirthDayOfYear);
        int nationalityId = hiddenTarget[39] & 0xFF;

        json.append("    ").append(quote("date of birth")).append(": {\n");
        appendNestedField(json, "block", quote(HIDDEN_BLOCK.name()), true);
        appendNestedField(json, "relativeOffset", Integer.toString(26), true);
        appendNestedField(json, "absoluteOffset", Integer.toString(hiddenWindow.offset() + 26), true);
        appendNestedField(json, "storage", quote("day_of_year_year_u16_le"), true);
        appendNestedField(json, "storedDayOfYear", Integer.toString(dateOfBirthDayOfYear), true);
        appendNestedField(json, "storedYear", Integer.toString(dateOfBirthYear), true);
        appendNestedField(json, "decodedValue", quote(dateOfBirth == null ? "invalid" : dateOfBirth.toString()), false);
        json.append("    },\n");
        emitted++;

        json.append("    ").append(quote("nationality")).append(": {\n");
        appendNestedField(json, "block", quote(HIDDEN_BLOCK.name()), true);
        appendNestedField(json, "relativeOffset", Integer.toString(39), true);
        appendNestedField(json, "absoluteOffset", Integer.toString(hiddenWindow.offset() + 39), true);
        appendNestedField(json, "storage", quote("country_id_u8"), true);
        appendNestedField(json, "storedValue", Integer.toString(nationalityId), true);
        appendNestedField(json, "decodedValue", quote(decodeNationality(nationalityId)), false);
        json.append("    },\n");
        emitted++;

        json.append("    ").append(quote("contract end")).append(": {\n");
        appendNestedField(json, "block", quote(CONTRACT_BLOCK.name()), true);
        appendNestedField(json, "relativeOffset", Integer.toString(8), true);
        appendNestedField(json, "absoluteOffset", Integer.toString(contractWindow.offset() + 8), true);
        appendNestedField(json, "storage", quote("day_of_year_year_u16_le"), true);
        appendNestedField(json, "storedDayOfYear", Integer.toString(contractEndDayOfYear), true);
        appendNestedField(json, "storedYear", Integer.toString(contractEndYear), true);
        appendNestedField(json, "decodedValue", quote(contractEnd == null ? "invalid" : contractEnd.toString()), false);
        json.append("    },\n");
        emitted++;

        for (WideFieldMapping mapping : GENERAL_FIELD_MAPPINGS) {
            int stored = mapping.encoding().decode(generalTarget, mapping.relativeOffset());
            json.append("    ").append(quote(mapping.name())).append(": {\n");
            appendNestedField(json, "block", quote(mapping.block().name()), true);
            appendNestedField(json, "relativeOffset", Integer.toString(mapping.relativeOffset()), true);
            appendNestedField(json, "absoluteOffset", Integer.toString(generalWindow.offset() + mapping.relativeOffset()), true);
            appendNestedField(json, "storage", quote(mapping.encoding().jsonName()), true);
            appendNestedField(json, "storedValue", Integer.toString(stored), true);
            appendNestedField(json, "decodedValue", Integer.toString(stored), false);
            json.append("    }");
            emitted++;
            if (emitted < totalFields) {
                json.append(',');
            }
            json.append('\n');
        }

        for (WideFieldMapping mapping : CONTRACT_FIELD_MAPPINGS) {
            int stored = mapping.encoding().decode(contractTarget, mapping.relativeOffset());
            json.append("    ").append(quote(mapping.name())).append(": {\n");
            appendNestedField(json, "block", quote(mapping.block().name()), true);
            appendNestedField(json, "relativeOffset", Integer.toString(mapping.relativeOffset()), true);
            appendNestedField(json, "absoluteOffset", Integer.toString(contractWindow.offset() + mapping.relativeOffset()), true);
            appendNestedField(json, "storage", quote(mapping.encoding().jsonName()), true);
            appendNestedField(json, "storedValue", Integer.toString(stored), true);
            appendNestedField(json, "decodedValue", Integer.toString(stored), false);
            json.append("    }");
            emitted++;
            if (emitted < totalFields) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  }\n");
        json.append("}\n");
        return json.toString();
    }

    private static ResolvedName resolveName(byte[] payload, byte[] hiddenTarget) {
        int firstNameId = WideValueEncoding.U32_LE.decode(hiddenTarget, FIRST_NAME_ID_OFFSET);
        int lastNameId = WideValueEncoding.U32_LE.decode(hiddenTarget, LAST_NAME_ID_OFFSET);
        String firstName = resolveKnownStringEntry(payload, FIRST_NAME_ENTRY_REFERENCE, firstNameId);
        if (firstName == null) {
            firstName = resolveStringById(payload, firstNameId, FIRST_NAME_TABLE_REFERENCE);
        }
        String lastName = resolveKnownStringEntry(payload, LAST_NAME_ENTRY_REFERENCE, lastNameId);
        if (lastName == null) {
            lastName = resolveStringById(payload, lastNameId, LAST_NAME_TABLE_REFERENCE);
        }
        return new ResolvedName(firstNameId, lastNameId, firstName, lastName, (firstName + " " + lastName).trim());
    }

    private static String resolveClubName(byte[] payload, int clubDatabaseId) {
        byte[] idBytes = new byte[]{
                (byte) (clubDatabaseId & 0xFF),
                (byte) ((clubDatabaseId >>> 8) & 0xFF),
                (byte) ((clubDatabaseId >>> 16) & 0xFF),
                (byte) ((clubDatabaseId >>> 24) & 0xFF)
        };
        for (int offset = 4; offset + 4 <= payload.length; offset++) {
            if (payload[offset] != idBytes[0]
                    || payload[offset + 1] != idBytes[1]
                    || payload[offset + 2] != idBytes[2]
                    || payload[offset + 3] != idBytes[3]) {
                continue;
            }
            for (int length = 1; length <= 64; length++) {
                int stringStart = offset - length;
                int lengthOffset = stringStart - 4;
                if (lengthOffset < 0) {
                    break;
                }
                if (WideValueEncoding.U32_LE.decode(payload, lengthOffset) != length) {
                    continue;
                }
                if (!looksLikeText(payload, stringStart, length)) {
                    continue;
                }
                return new String(payload, stringStart, length, StandardCharsets.UTF_8);
            }
        }
        return "club_id_" + clubDatabaseId;
    }

    private static String resolveKnownStringEntry(byte[] payload, int entryOffset, int expectedId) {
        if (entryOffset < 0 || entryOffset + 8 > payload.length) {
            return null;
        }
        if (WideValueEncoding.U32_LE.decode(payload, entryOffset) != expectedId) {
            return null;
        }
        int length = WideValueEncoding.U32_LE.decode(payload, entryOffset + 4);
        if (length <= 0 || length > 64 || entryOffset + 8 + length > payload.length) {
            return null;
        }
        if (!looksLikeText(payload, entryOffset + 8, length)) {
            return null;
        }
        return new String(payload, entryOffset + 8, length, StandardCharsets.UTF_8);
    }

    private static String resolveStringById(byte[] payload, int stringId, int preferredOffset) {
        String best = null;
        int bestScore = Integer.MIN_VALUE;
        for (int offset = 0; offset + 8 < payload.length; offset++) {
            if (WideValueEncoding.U32_LE.decode(payload, offset) != stringId) {
                continue;
            }
            int length = WideValueEncoding.U32_LE.decode(payload, offset + 4);
            if (length <= 0 || length > 64 || offset + 8 + length > payload.length) {
                continue;
            }
            if (!looksLikeText(payload, offset + 8, length)) {
                continue;
            }
            String candidate = new String(payload, offset + 8, length, StandardCharsets.UTF_8);
            int score = scoreStringCandidate(payload, offset, stringId, length, preferredOffset);
            if (score == Integer.MIN_VALUE) {
                continue;
            }
            if (score > bestScore) {
                bestScore = score;
                best = candidate;
            }
        }
        return best == null ? "string_id_" + stringId : best;
    }

    private static int scoreStringCandidate(byte[] payload, int offset, int stringId, int length, int preferredOffset) {
        boolean hasChain = false;
        int currentOffset = offset;
        int currentId = stringId;
        int currentLength = length;
        for (int step = 0; step < 6; step++) {
            int nextOffset = currentOffset + 8 + currentLength;
            if (nextOffset + 8 > payload.length) {
                break;
            }
            int nextId = WideValueEncoding.U32_LE.decode(payload, nextOffset);
            int nextLength = WideValueEncoding.U32_LE.decode(payload, nextOffset + 4);
            if (nextId != currentId + 1) {
                break;
            }
            if (nextLength <= 0 || nextLength > 64 || nextOffset + 8 + nextLength > payload.length) {
                break;
            }
            if (!looksLikeText(payload, nextOffset + 8, nextLength)) {
                break;
            }
            hasChain = true;
            currentOffset = nextOffset;
            currentId = nextId;
            currentLength = nextLength;
        }
        if (!hasChain) {
            return Integer.MIN_VALUE;
        }
        return -Math.abs(offset - preferredOffset);
    }

    private static boolean looksLikeText(byte[] payload, int start, int length) {
        String decoded = new String(payload, start, length, StandardCharsets.UTF_8);
        if (decoded.indexOf('\uFFFD') >= 0) {
            return false;
        }
        for (int i = 0; i < decoded.length(); i++) {
            if (Character.isLetter(decoded.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static LocalDate decodeDayOfYear(int year, int dayOfYear) {
        if (year < 1900 || year > 2500 || dayOfYear < 1 || dayOfYear > 366) {
            return null;
        }
        try {
            return LocalDate.ofYearDay(year, dayOfYear);
        } catch (RuntimeException exception) {
            return null;
        }
    }

    private static String decodeNationality(int nationalityId) {
        return NATIONALITY_NAMES.getOrDefault(nationalityId, "country_id_" + nationalityId);
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

    private record WideFieldMapping(String name, BlockDefinition block, int relativeOffset, WideValueEncoding encoding) {
    }

    private record ResolvedName(int firstNameId, int lastNameId, String firstName, String lastName, String fullName) {
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

    private enum WideValueEncoding {
        U16_LE("u16_le") {
            @Override
            int decode(byte[] block, int offset) {
                return (block[offset] & 0xFF) | ((block[offset + 1] & 0xFF) << 8);
            }
        },
        U32_LE("u32_le") {
            @Override
            int decode(byte[] block, int offset) {
                return (block[offset] & 0xFF)
                        | ((block[offset + 1] & 0xFF) << 8)
                        | ((block[offset + 2] & 0xFF) << 16)
                        | ((block[offset + 3] & 0xFF) << 24);
            }
        };

        private final String jsonName;

        WideValueEncoding(String jsonName) {
            this.jsonName = jsonName;
        }

        private String jsonName() {
            return jsonName;
        }

        abstract int decode(byte[] block, int offset);
    }
}
