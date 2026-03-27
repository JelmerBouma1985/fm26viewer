package com.fm26.save.analysis;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.List;

public final class WeakPreambleDebugProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: WeakPreambleDebugProbe <save> <playerId> [playerId...]");
            System.exit(1);
        }
        Class<?> extractor = GenericPlayerSubsetExtractor.class;
        Method loadPayload = extractor.getDeclaredMethod("loadPayload", Path.class);
        loadPayload.setAccessible(true);
        Method hasStrongPlayerPreamble = extractor.getDeclaredMethod("hasStrongPlayerPreamble", byte[].class, int.class);
        hasStrongPlayerPreamble.setAccessible(true);
        Method hasWeakStandardPersonPreamble = extractor.getDeclaredMethod("hasWeakStandardPersonPreamble", byte[].class, int.class);
        hasWeakStandardPersonPreamble.setAccessible(true);
        Method hasWeakStandardPlayerShape = extractor.getDeclaredMethod("hasWeakStandardPlayerShape", byte[].class, int.class);
        hasWeakStandardPlayerShape.setAccessible(true);
        Method inferStandardVisibleCandidate = extractor.getDeclaredMethod("inferStandardVisibleCandidate", byte[].class, int.class);
        inferStandardVisibleCandidate.setAccessible(true);
        Method decideFamily = extractor.getDeclaredMethod("decideFamily", byte[].class, int.class);
        decideFamily.setAccessible(true);
        Method buildStandardVisibleVariant = extractor.getDeclaredMethod("buildStandardVisibleVariant", byte[].class, int.class);
        buildStandardVisibleVariant.setAccessible(true);
        Method extract = extractor.getDeclaredMethod("extract", Path.class);
        extract.setAccessible(true);
        Method missingAbilityWindow = extractor.getDeclaredMethod("missingAbilityWindow", Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$VariantResult"));
        missingAbilityWindow.setAccessible(true);
        Method shouldRejectTailCandidate = extractor.getDeclaredMethod("shouldRejectTailCandidate", byte[].class, int.class, String.class, Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$VariantResult"));
        shouldRejectTailCandidate.setAccessible(true);

        Class<?> inferredClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$InferredStandardCandidate");
        Method startDelta = inferredClass.getDeclaredMethod("startDelta");
        Method score = inferredClass.getDeclaredMethod("score");
        startDelta.setAccessible(true);
        score.setAccessible(true);
        Class<?> familyDecisionClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$FamilyDecision");
        Method familyName = familyDecisionClass.getDeclaredMethod("name");
        Method familyScore = familyDecisionClass.getDeclaredMethod("score");
        familyName.setAccessible(true);
        familyScore.setAccessible(true);
        Class<?> variantClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$VariantResult");
        Method variantName = variantClass.getDeclaredMethod("name");
        Method variantScore = variantClass.getDeclaredMethod("score");
        Method variantInvalidCount = variantClass.getDeclaredMethod("invalidCount");
        Method variantDecoded = variantClass.getDeclaredMethod("decoded");
        variantName.setAccessible(true);
        variantScore.setAccessible(true);
        variantInvalidCount.setAccessible(true);
        variantDecoded.setAccessible(true);
        Class<?> extractionResultClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ExtractionResult");
        Method playersMethod = extractionResultClass.getDeclaredMethod("players");
        playersMethod.setAccessible(true);
        Class<?> extractedPlayerClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ExtractedPlayer");
        Method extractedId = extractedPlayerClass.getDeclaredMethod("id");
        Method extractedFullName = extractedPlayerClass.getDeclaredMethod("fullName");
        extractedId.setAccessible(true);
        extractedFullName.setAccessible(true);

        Object extraction = extract.invoke(null, Path.of(args[0]));
        @SuppressWarnings("unchecked")
        List<Object> extractedPlayers = (List<Object>) playersMethod.invoke(extraction);

        byte[] payload = (byte[]) loadPayload.invoke(null, Path.of(args[0]));
        for (int i = 1; i < args.length; i++) {
            int playerId = Integer.parseInt(args[i]);
            Integer personPair = findDuplicatePairOffset(payload, playerId, 65_000_000, 90_000_000);
            System.out.println("playerId=" + playerId + " personPair=" + personPair);
            Object extractedPlayer = extractedPlayers.stream()
                    .filter(p -> {
                        try {
                            return ((int) extractedId.invoke(p)) == playerId;
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .findFirst()
                    .orElse(null);
            System.out.println("  inExtract=" + (extractedPlayer != null)
                    + (extractedPlayer == null ? "" : " extractedFullName=" + extractedFullName.invoke(extractedPlayer)));
            if (personPair == null) {
                continue;
            }
            Object inferred = inferStandardVisibleCandidate.invoke(null, payload, personPair);
            System.out.println("  strong=" + hasStrongPlayerPreamble.invoke(null, payload, personPair));
            System.out.println("  weakPreamble=" + hasWeakStandardPersonPreamble.invoke(null, payload, personPair));
            System.out.println("  weakShape=" + hasWeakStandardPlayerShape.invoke(null, payload, personPair));
            Object family = decideFamily.invoke(null, payload, personPair);
            Object variant = buildStandardVisibleVariant.invoke(null, payload, personPair);
            @SuppressWarnings("unchecked")
            java.util.Map<String, Integer> decoded = (java.util.Map<String, Integer>) variantDecoded.invoke(variant);
            System.out.println("  family=" + familyName.invoke(family) + " familyScore=" + familyScore.invoke(family));
            System.out.println("  variant=" + variantName.invoke(variant)
                    + " score=" + variantScore.invoke(variant)
                    + " invalid=" + variantInvalidCount.invoke(variant)
                    + " ca=" + decoded.get("current_ability")
                    + " pa=" + decoded.get("potential_ability"));
            System.out.println("  missingAbility=" + missingAbilityWindow.invoke(null, variant));
            System.out.println("  rejectTail=" + shouldRejectTailCandidate.invoke(null, payload, personPair, familyName.invoke(family), variant));
            if (inferred != null) {
                System.out.println("  inferredDelta=" + startDelta.invoke(inferred) + " score=" + score.invoke(inferred));
            } else {
                System.out.println("  inferredDelta=null");
            }
        }
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
