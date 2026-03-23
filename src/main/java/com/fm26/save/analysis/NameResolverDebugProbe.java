package com.fm26.save.analysis;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public final class NameResolverDebugProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: NameResolverDebugProbe <save> <playerId> [playerId...]");
            System.exit(1);
        }
        Class<?> extractor = GenericPlayerSubsetExtractor.class;
        Method loadPayload = extractor.getDeclaredMethod("loadPayload", Path.class);
        loadPayload.setAccessible(true);
        Method findLikelyPlayers = extractor.getDeclaredMethod("findLikelyPlayers", byte[].class);
        findLikelyPlayers.setAccessible(true);
        Method buildNameTables = extractor.getDeclaredMethod("buildNameTables", byte[].class);
        buildNameTables.setAccessible(true);
        Method resolveName = extractor.getDeclaredMethod("resolveName", byte[].class, int.class, Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$NameTables"));
        resolveName.setAccessible(true);

        byte[] payload = (byte[]) loadPayload.invoke(null, Path.of(args[0]));
        @SuppressWarnings("unchecked")
        List<Object> candidates = (List<Object>) findLikelyPlayers.invoke(null, (Object) payload);
        Object nameTables = buildNameTables.invoke(null, (Object) payload);

        Method idMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$PlayerCandidate").getDeclaredMethod("id");
        Method personPairMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$PlayerCandidate").getDeclaredMethod("personPair");
        idMethod.setAccessible(true);
        personPairMethod.setAccessible(true);

        Method firstNameMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ResolvedName").getDeclaredMethod("firstName");
        Method lastNameMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ResolvedName").getDeclaredMethod("lastName");
        Method fullNameMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ResolvedName").getDeclaredMethod("fullName");
        firstNameMethod.setAccessible(true);
        lastNameMethod.setAccessible(true);
        fullNameMethod.setAccessible(true);

        Method firstNamesMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$NameTables").getDeclaredMethod("firstNames");
        Method lastNamesMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$NameTables").getDeclaredMethod("lastNames");
        Method commonNamesMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$NameTables").getDeclaredMethod("commonNames");
        firstNamesMethod.setAccessible(true);
        lastNamesMethod.setAccessible(true);
        commonNamesMethod.setAccessible(true);

        Method scoredValueMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ScoredString").getDeclaredMethod("value");
        Method scoredScoreMethod = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ScoredString").getDeclaredMethod("score");
        scoredValueMethod.setAccessible(true);
        scoredScoreMethod.setAccessible(true);

        @SuppressWarnings("unchecked")
        Map<Integer, Object> firstNames = (Map<Integer, Object>) firstNamesMethod.invoke(nameTables);
        @SuppressWarnings("unchecked")
        Map<Integer, Object> lastNames = (Map<Integer, Object>) lastNamesMethod.invoke(nameTables);
        @SuppressWarnings("unchecked")
        Map<Integer, Object> commonNames = (Map<Integer, Object>) commonNamesMethod.invoke(nameTables);

        Method scoreDelta = extractor.getDeclaredMethod("scoreDelta", int.class);
        scoreDelta.setAccessible(true);
        Method decodeInlineName = extractor.getDeclaredMethod("decodeInlineName", byte[].class, int.class);
        decodeInlineName.setAccessible(true);

        for (int i = 1; i < args.length; i++) {
            int playerId = Integer.parseInt(args[i]);
            Object candidate = candidates.stream()
                    .filter(c -> {
                        try {
                            return ((int) idMethod.invoke(c)) == playerId;
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .findFirst()
                    .orElse(null);
            if (candidate == null) {
                System.out.println(playerId + " not found");
                continue;
            }
            int personPair = (int) personPairMethod.invoke(candidate);
            Object resolved = resolveName.invoke(null, payload, personPair, nameTables);
            System.out.println(
                    "playerId=" + playerId
                            + " personPair=" + personPair
                            + " firstName=" + firstNameMethod.invoke(resolved)
                            + " lastName=" + lastNameMethod.invoke(resolved)
                            + " fullName=" + fullNameMethod.invoke(resolved)
            );
            for (int delta = -800; delta <= -100; delta++) {
                int firstOffset = personPair + delta;
                int lastOffset = firstOffset + 5;
                if (firstOffset < 0 || lastOffset + 18 >= payload.length) {
                    continue;
                }
                if ((payload[firstOffset + 4] & 0xFF) != 0) {
                    continue;
                }
                int firstNameId = u32le(payload, firstOffset);
                int lastNameId = u32le(payload, lastOffset);
                int commonNameId = u32le(payload, firstOffset + 10);
                Object first = firstNames.get(firstNameId);
                Object last = lastNames.get(lastNameId);
                Object common = commonNameId == -1 ? null : commonNames.get(commonNameId);
                if ((first == null || last == null) && common == null) {
                    continue;
                }
                int score = (int) scoreDelta.invoke(null, delta);
                if (first != null) {
                    score += (int) scoredScoreMethod.invoke(first);
                }
                if (last != null) {
                    score += (int) scoredScoreMethod.invoke(last);
                }
                if (common != null) {
                    score += 20;
                } else if (commonNameId == -1) {
                    score += 3;
                }
                if (first != null && last != null && common != null) {
                    String firstValue = (String) scoredValueMethod.invoke(first);
                    String commonValue = (String) scoredValueMethod.invoke(common);
                    if (commonValue.equals(firstValue)
                            || firstValue.startsWith(commonValue + " ")
                            || commonValue.startsWith(firstValue + " ")) {
                        score += 30;
                    }
                }
                if ((payload[firstOffset + 10] & 0xFF) == 0xFF
                        && (payload[firstOffset + 11] & 0xFF) == 0xFF
                        && (payload[firstOffset + 12] & 0xFF) == 0xFF
                        && (payload[firstOffset + 13] & 0xFF) == 0xFF) {
                    score += 8;
                }
                if ((payload[firstOffset + 9] & 0xFF) == 0) {
                    score += 3;
                }
                if ((payload[firstOffset + 14] & 0xFF) == 0) {
                    score += 3;
                }
                if ((payload[firstOffset + 16] & 0xFF) == 0
                        && (payload[firstOffset + 17] & 0xFF) == 0
                        && (payload[firstOffset + 18] & 0xFF) == 0) {
                    score += 3;
                }
                String inline = (String) decodeInlineName.invoke(null, payload, firstOffset);
                if (inline != null) {
                    score += 10;
                    if (first != null && inline.contains((String) scoredValueMethod.invoke(first))) {
                        score += 10;
                    }
                    if (last != null && inline.contains((String) scoredValueMethod.invoke(last))) {
                        score += 10;
                    }
                }
                if (score >= 70) {
                    System.out.println(
                            "  candidate delta=" + delta
                                    + " score=" + score
                                    + " first=" + (first == null ? null : scoredValueMethod.invoke(first))
                                    + " last=" + (last == null ? null : scoredValueMethod.invoke(last))
                                    + " common=" + (common == null ? null : scoredValueMethod.invoke(common))
                                    + " inline=" + inline
                    );
                }
            }
        }
    }

    private static int u32le(byte[] payload, int offset) {
        return (payload[offset] & 0xFF)
                | ((payload[offset + 1] & 0xFF) << 8)
                | ((payload[offset + 2] & 0xFF) << 16)
                | ((payload[offset + 3] & 0xFF) << 24);
    }
}
