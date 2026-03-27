package com.fm26.save.analysis;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class LikelyVsProfiledProbe {

    public static void main(String[] args) throws Exception {
        Path save = args.length > 0 ? Path.of(args[0]) : Path.of("games/Feyenoord_after.fm");

        Class<?> extractor = GenericPlayerSubsetExtractor.class;
        Method loadPayload = extractor.getDeclaredMethod("loadPayload", Path.class);
        loadPayload.setAccessible(true);
        Method findLikelyPlayers = extractor.getDeclaredMethod("findLikelyPlayers", byte[].class);
        findLikelyPlayers.setAccessible(true);
        Method extract = extractor.getDeclaredMethod("extract", Path.class);
        extract.setAccessible(true);

        byte[] payload = (byte[]) loadPayload.invoke(null, save);
        @SuppressWarnings("unchecked")
        List<Object> likely = (List<Object>) findLikelyPlayers.invoke(null, (Object) payload);
        Object result = extract.invoke(null, save);

        Class<?> playerCandidateClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$PlayerCandidate");
        Method idMethod = playerCandidateClass.getDeclaredMethod("id");
        idMethod.setAccessible(true);

        Class<?> extractionResultClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ExtractionResult");
        Method playersMethod = extractionResultClass.getDeclaredMethod("players");
        playersMethod.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Object> profiled = (List<Object>) playersMethod.invoke(result);

        Class<?> extractedPlayerClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ExtractedPlayer");
        Method extractedIdMethod = extractedPlayerClass.getDeclaredMethod("id");
        extractedIdMethod.setAccessible(true);

        Set<Integer> profiledIds = new HashSet<>();
        for (Object p : profiled) {
            profiledIds.add((Integer) extractedIdMethod.invoke(p));
        }

        List<Integer> missing = new ArrayList<>();
        for (Object c : likely) {
            int id = (Integer) idMethod.invoke(c);
            if (!profiledIds.contains(id)) {
                missing.add(id);
            }
        }

        System.out.println("likely=" + likely.size());
        System.out.println("profiled=" + profiled.size());
        System.out.println("missing=" + missing.size());
        for (Integer id : missing) {
            System.out.println(id);
        }
    }
}
