package com.fm26.save.analysis;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class StandardVisibleOnlyProbe {

    private static final Set<Integer> TARGET_IDS = Set.of(
            133888,
            350464,
            350976,
            676608,
            929798,
            5_625_973,
            5_667_723,
            8_169_242,
            53_084_160
    );

    private StandardVisibleOnlyProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path save = args.length == 0 ? Path.of("games/Feyenoord_after.fm") : Path.of(args[0]);

        Class<?> extractor = GenericPlayerSubsetExtractor.class;
        Method loadPayload = extractor.getDeclaredMethod("loadPayload", Path.class);
        Method findLikelyPlayers = extractor.getDeclaredMethod("findLikelyPlayers", byte[].class);
        Method buildNameTables = extractor.getDeclaredMethod("buildNameTables", byte[].class);
        Method buildStandardVisibleVariant = extractor.getDeclaredMethod("buildStandardVisibleVariant", byte[].class, int.class);
        Method buildLowAnchorStandardVisibleVariant = extractor.getDeclaredMethod("buildLowAnchorStandardVisibleVariant", byte[].class, int.class);
        Method enrichVariant = extractor.getDeclaredMethod("enrichVariant", byte[].class, int.class, Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$VariantResult"));
        Method resolveName = extractor.getDeclaredMethod("resolveName", byte[].class, int.class, Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$NameTables"));
        Method resolveLowAnchorInlineName = extractor.getDeclaredMethod("resolveLowAnchorInlineName", byte[].class, int.class, Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$NameTables"));
        Method missingAbilityWindow = extractor.getDeclaredMethod("missingAbilityWindow", Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$VariantResult"));
        Method shouldRejectTailCandidate = extractor.getDeclaredMethod("shouldRejectTailCandidate", byte[].class, int.class, String.class, Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$VariantResult"));

        loadPayload.setAccessible(true);
        findLikelyPlayers.setAccessible(true);
        buildNameTables.setAccessible(true);
        buildStandardVisibleVariant.setAccessible(true);
        buildLowAnchorStandardVisibleVariant.setAccessible(true);
        enrichVariant.setAccessible(true);
        resolveName.setAccessible(true);
        resolveLowAnchorInlineName.setAccessible(true);
        missingAbilityWindow.setAccessible(true);
        shouldRejectTailCandidate.setAccessible(true);

        byte[] payload = (byte[]) loadPayload.invoke(null, save);
        @SuppressWarnings("unchecked")
        List<Object> likely = (List<Object>) findLikelyPlayers.invoke(null, payload);
        Object nameTables = buildNameTables.invoke(null, payload);

        Class<?> candidateClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$PlayerCandidate");
        Method candidateId = candidateClass.getDeclaredMethod("id");
        Method candidatePersonPair = candidateClass.getDeclaredMethod("personPair");
        Method candidateExtraPair = candidateClass.getDeclaredMethod("extraPair");
        candidateId.setAccessible(true);
        candidatePersonPair.setAccessible(true);
        candidateExtraPair.setAccessible(true);

        Class<?> variantClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$VariantResult");
        Method variantName = variantClass.getDeclaredMethod("name");
        Method variantScore = variantClass.getDeclaredMethod("score");
        Method variantInvalidCount = variantClass.getDeclaredMethod("invalidCount");
        Method variantDecoded = variantClass.getDeclaredMethod("decoded");
        variantName.setAccessible(true);
        variantScore.setAccessible(true);
        variantInvalidCount.setAccessible(true);
        variantDecoded.setAccessible(true);

        Class<?> resolvedNameClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ResolvedName");
        Method resolvedFirstName = resolvedNameClass.getDeclaredMethod("firstName");
        Method resolvedLastName = resolvedNameClass.getDeclaredMethod("lastName");
        Method resolvedFullName = resolvedNameClass.getDeclaredMethod("fullName");
        resolvedFirstName.setAccessible(true);
        resolvedLastName.setAccessible(true);
        resolvedFullName.setAccessible(true);

        Constructor<?> resolvedNameCtor = resolvedNameClass.getDeclaredConstructor(String.class, String.class, String.class);
        resolvedNameCtor.setAccessible(true);

        Set<Integer> seenTargets = new LinkedHashSet<>();
        List<String> lines = new ArrayList<>();
        for (Object candidate : likely) {
            int id = (int) candidateId.invoke(candidate);
            if (!TARGET_IDS.contains(id)) {
                continue;
            }
            seenTargets.add(id);
            int personPair = (int) candidatePersonPair.invoke(candidate);
            int extraPair = (int) candidateExtraPair.invoke(candidate);

            List<Object> variants = new ArrayList<>();
            Object standard = buildStandardVisibleVariant.invoke(null, payload, personPair);
            variants.add(standard);
            if (id > 0 && id < 10_000) {
                Object lowAnchor = buildLowAnchorStandardVisibleVariant.invoke(null, payload, id);
                @SuppressWarnings("unchecked")
                Map<String, Integer> lowDecoded = (Map<String, Integer>) variantDecoded.invoke(lowAnchor);
                if (!lowDecoded.isEmpty()) {
                    variants.add(lowAnchor);
                }
            }

            Object best = variants.stream()
                    .max(Comparator
                            .comparingInt(v -> invokeInt(variantScore, v))
                            .thenComparingInt(v -> variantPriority(invokeString(variantName, v)))
                            .thenComparingInt(v -> -invokeInt(variantInvalidCount, v)))
                    .orElseThrow();
            best = enrichVariant.invoke(null, payload, personPair, best);

            Object resolvedName = resolveName.invoke(null, payload, personPair, nameTables);
            if ("standard_visible_low_anchor".equals(invokeString(variantName, best))) {
                Object lowAnchorName = resolveLowAnchorInlineName.invoke(null, payload, id, nameTables);
                String lowFull = (String) resolvedFullName.invoke(lowAnchorName);
                String currentFull = (String) resolvedFullName.invoke(resolvedName);
                String currentLast = (String) resolvedLastName.invoke(resolvedName);
                if (lowFull != null
                        && !lowFull.isBlank()
                        && (currentFull == null || currentFull.isBlank() || currentLast == null || !lowFull.equals(currentFull))) {
                    resolvedName = lowAnchorName;
                }
            }

            boolean missingAbility = (boolean) missingAbilityWindow.invoke(null, best);
            boolean rejectTail = (boolean) shouldRejectTailCandidate.invoke(null, payload, personPair, "standard_visible", best);
            @SuppressWarnings("unchecked")
            Map<String, Integer> decoded = (Map<String, Integer>) variantDecoded.invoke(best);
            Integer ca = decoded.get("current_ability");
            Integer pa = decoded.get("potential_ability");

            lines.add("{"
                    + "\"id\":" + id
                    + ",\"personPair\":" + personPair
                    + ",\"extraPair\":" + extraPair
                    + ",\"forcedVariant\":\"" + invokeString(variantName, best) + "\""
                    + ",\"score\":" + invokeInt(variantScore, best)
                    + ",\"invalidCount\":" + invokeInt(variantInvalidCount, best)
                    + ",\"currentAbility\":" + (ca == null ? "null" : ca)
                    + ",\"potentialAbility\":" + (pa == null ? "null" : pa)
                    + ",\"missingAbilityWindow\":" + missingAbility
                    + ",\"rejectTail\":" + rejectTail
                    + ",\"fullName\":" + jsonString((String) resolvedFullName.invoke(resolvedName))
                    + ",\"firstName\":" + jsonString((String) resolvedFirstName.invoke(resolvedName))
                    + ",\"lastName\":" + jsonString((String) resolvedLastName.invoke(resolvedName))
                    + ",\"decodedFieldCount\":" + decoded.size()
                    + "}");
        }

        for (Integer id : TARGET_IDS.stream().sorted().toList()) {
            if (!seenTargets.contains(id)) {
                lines.add("{\"id\":" + id + ",\"status\":\"not_likely_player\"}");
            }
        }
        lines.sort(Comparator.naturalOrder());
        System.out.println("[");
        for (int i = 0; i < lines.size(); i++) {
            System.out.print("  " + lines.get(i));
            if (i + 1 < lines.size()) {
                System.out.print(",");
            }
            System.out.println();
        }
        System.out.println("]");
    }

    private static int variantPriority(String variantName) {
        return switch (variantName) {
            case "standard_visible" -> 100;
            case "standard_visible_low_anchor" -> 99;
            default -> 0;
        };
    }

    private static int invokeInt(Method method, Object target) {
        try {
            return (int) method.invoke(target);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String invokeString(Method method, Object target) {
        try {
            return (String) method.invoke(target);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String jsonString(String value) {
        if (value == null) {
            return "null";
        }
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"") + "\"";
    }
}
