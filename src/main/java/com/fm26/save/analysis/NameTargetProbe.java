package com.fm26.save.analysis;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public final class NameTargetProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("usage: NameTargetProbe <save> <playerId> <needle1> <needle2>");
            System.exit(1);
        }
        String save = args[0];
        int playerId = Integer.parseInt(args[1]);
        String needle1 = args[2];
        String needle2 = args[3];

        Class<?> extractor = GenericPlayerSubsetExtractor.class;
        Method loadPayload = extractor.getDeclaredMethod("loadPayload", Path.class);
        loadPayload.setAccessible(true);
        Method buildNameTables = extractor.getDeclaredMethod("buildNameTables", byte[].class);
        buildNameTables.setAccessible(true);
        Method decodeInlineName = extractor.getDeclaredMethod("decodeInlineName", byte[].class, int.class);
        decodeInlineName.setAccessible(true);
        Method scoreDelta = extractor.getDeclaredMethod("scoreDelta", int.class);
        scoreDelta.setAccessible(true);

        Class<?> nameTablesClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$NameTables");
        Method firstNamesMethod = nameTablesClass.getDeclaredMethod("firstNames");
        Method lastNamesMethod = nameTablesClass.getDeclaredMethod("lastNames");
        Method commonNamesMethod = nameTablesClass.getDeclaredMethod("commonNames");
        firstNamesMethod.setAccessible(true);
        lastNamesMethod.setAccessible(true);
        commonNamesMethod.setAccessible(true);

        Class<?> scoredStringClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ScoredString");
        Method valueMethod = scoredStringClass.getDeclaredMethod("value");
        valueMethod.setAccessible(true);

        byte[] payload = (byte[]) loadPayload.invoke(null, Path.of(save));
        Object tables = buildNameTables.invoke(null, (Object) payload);
        @SuppressWarnings("unchecked")
        Map<Integer, Object> firstNames = (Map<Integer, Object>) firstNamesMethod.invoke(tables);
        @SuppressWarnings("unchecked")
        Map<Integer, Object> lastNames = (Map<Integer, Object>) lastNamesMethod.invoke(tables);
        @SuppressWarnings("unchecked")
        Map<Integer, Object> commonNames = (Map<Integer, Object>) commonNamesMethod.invoke(tables);

        Integer personPair = findDuplicatePairOffset(payload, playerId, 65_000_000, 90_000_000);
        System.out.println("playerId=" + playerId + " personPair=" + personPair);
        if (personPair == null) {
            return;
        }
        for (int delta = -2500; delta <= -100; delta++) {
            int firstOffset = personPair + delta;
            int lastOffset = firstOffset + 5;
            if (firstOffset < 0 || lastOffset + 18 >= payload.length) {
                continue;
            }
            if ((payload[firstOffset + 4] & 0xFF) != 0) {
                continue;
            }
            int firstId = u32le(payload, firstOffset);
            int lastId = u32le(payload, lastOffset);
            int commonId = u32le(payload, firstOffset + 10);
            String first = resolve(firstNames, firstId, valueMethod);
            String last = resolve(lastNames, lastId, valueMethod);
            String common = commonId == -1 ? null : resolve(commonNames, commonId, valueMethod);
            String inline = (String) decodeInlineName.invoke(null, payload, firstOffset);
            String hay = String.join(" | ",
                    first == null ? "" : first,
                    last == null ? "" : last,
                    common == null ? "" : common,
                    inline == null ? "" : inline);
            if (!containsIgnoreCase(hay, needle1) && !containsIgnoreCase(hay, needle2)) {
                continue;
            }
            int score = (int) scoreDelta.invoke(null, delta);
            System.out.println("delta=" + delta
                    + " score=" + score
                    + " first=" + first
                    + " last=" + last
                    + " common=" + common
                    + " inline=" + inline);
        }
    }

    private static boolean containsIgnoreCase(String hay, String needle) {
        return hay != null && needle != null && !needle.isBlank()
                && hay.toLowerCase().contains(needle.toLowerCase());
    }

    private static String resolve(Map<Integer, Object> table, int id, Method valueMethod) throws Exception {
        Object value = table.get(id);
        return value == null ? null : (String) valueMethod.invoke(value);
    }

    private static Integer findDuplicatePairOffset(byte[] payload, int playerId, int minOffset, int maxOffset) {
        for (int offset = Math.max(0, minOffset); offset + 8 <= payload.length && offset < maxOffset; offset++) {
            if (u32le(payload, offset) == playerId && u32le(payload, offset + 4) == playerId) {
                return offset;
            }
        }
        return null;
    }

    private static int u32le(byte[] payload, int offset) {
        return (payload[offset] & 0xFF)
                | ((payload[offset + 1] & 0xFF) << 8)
                | ((payload[offset + 2] & 0xFF) << 16)
                | ((payload[offset + 3] & 0xFF) << 24);
    }
}
