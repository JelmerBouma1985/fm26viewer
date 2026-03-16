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

public final class GenericPlayerSubsetExtractor {

    private static final int FMF_ZSTD_OFFSET = 26;
    private static final int DUP_PAIR_DISTANCE = 4;
    private static final int PERSON_BLOCK_MIN_OFFSET = 65_000_000;
    private static final int PERSON_BLOCK_MAX_OFFSET = 90_000_000;
    private static final int PLAYER_EXTRA_MIN_OFFSET = 100_000_000;
    private static final int MIN_ACCEPTABLE_SCORE = 4;
    private static final int FAMILY_MARGIN = 2;
    private static final String ALT_PLAYER_SIGNATURE = "ytrp|ytgh|tanN|....|gh..";
    private static final int STANDARD_SEARCH_MIN_DELTA = -1_910;
    private static final int STANDARD_SEARCH_MAX_DELTA = -450;

    private static final Map<String, Integer> STANDARD_VISIBLE_FIELDS = Map.ofEntries(
            Map.entry("crossing", -2),
            Map.entry("dribbling", -1),
            Map.entry("finishing", 0),
            Map.entry("heading", 1),
            Map.entry("long_shots", 2),
            Map.entry("marking", 3),
            Map.entry("off_the_ball", 4),
            Map.entry("passing", 5),
            Map.entry("penalty_taking", 6),
            Map.entry("tackling", 7),
            Map.entry("vision", 8),
            Map.entry("anticipation", 15),
            Map.entry("decisions", 16),
            Map.entry("positioning", 18),
            Map.entry("first_touch", 20),
            Map.entry("technique", 21),
            Map.entry("flair", 24),
            Map.entry("corners", 25),
            Map.entry("teamwork", 26),
            Map.entry("work_rate", 27),
            Map.entry("long_throws", 28),
            Map.entry("acceleration", 32),
            Map.entry("free_kicks", 33),
            Map.entry("strength", 34),
            Map.entry("stamina", 35),
            Map.entry("pace", 36),
            Map.entry("jumping_reach", 37),
            Map.entry("leadership", 38),
            Map.entry("balance", 40),
            Map.entry("bravery", 41),
            Map.entry("aggression", 43),
            Map.entry("agility", 44),
            Map.entry("natural_fitness", 48),
            Map.entry("determination", 49),
            Map.entry("composure", 50),
            Map.entry("concentration", 51)
    );

    private static final int[] STANDARD_INFERENCE_POSITIONS = {
            0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 18, 20, 21, 24, 25, 26, 27, 28,
            32, 33, 34, 35, 36, 37, 38, 40, 41, 43, 44, 48, 49, 50, 51
    };

    private static final LayoutVariant TRAUNER = new LayoutVariant(
            "trauner",
            Map.of(
                    "potential_ability", new Spec(-1192 + 8, Enc.U16LE),
                    "striker", new Spec(-1160 + 10, Enc.U8),
                    "finishing", new Spec(-1145, Enc.TIMES5),
                    "pace", new Spec(-1145 + 36, Enc.TIMES5),
                    "concentration", new Spec(-1145 + 51, Enc.TIMES5),
                    "controversy", new Spec(-236 + 54, Enc.U8)
            )
    );

    private static final LayoutVariant SMAL = new LayoutVariant(
            "smal",
            Map.of(
                    "potential_ability", new Spec(5165, Enc.U16LE),
                    "striker", new Spec(5199, Enc.U8),
                    "finishing", new Spec(5204, Enc.TIMES5),
                    "pace", new Spec(5240, Enc.TIMES5),
                    "concentration", new Spec(5255, Enc.TIMES5),
                    "controversy", new Spec(5987, Enc.U8)
            )
    );

    private static final LayoutVariant KOOISTRA = new LayoutVariant(
            "kooistra",
            Map.of(
                    "ambition", new Spec(-126, Enc.U8),
                    "defensive_midfielder", new Spec(-713, Enc.U8),
                    "marking", new Spec(-698, Enc.TIMES5_PLUS_ONE_FLOOR),
                    "dribbling", new Spec(-702, Enc.TIMES5_PLUS_ONE_FLOOR),
                    "leadership", new Spec(-663, Enc.TIMES5_PLUS_ONE_FLOOR),
                    "concentration", new Spec(-650, Enc.TIMES5_PLUS_ONE_FLOOR),
                    "stamina", new Spec(-666, Enc.TIMES5_PLUS_ONE_FLOOR),
                    "strength", new Spec(-667, Enc.TIMES5_PLUS_ONE_FLOOR)
            )
    );

    private static final LayoutVariant AIDOO = new LayoutVariant(
            "aidoo",
            Map.of(
                    "defensive_midfielder", new Spec(-1162, Enc.U8),
                    "ambition", new Spec(8163, Enc.U8),
                    "dribbling", new Spec(-17407, Enc.TIMES5),
                    "marking", new Spec(-9400, Enc.TIMES5),
                    "leadership", new Spec(10393, Enc.TIMES5),
                    "concentration", new Spec(10401, Enc.TIMES5),
                    "stamina", new Spec(-6978, Enc.TIMES5)
            )
    );

    private static final LayoutVariant FORWARD_LOCAL = new LayoutVariant(
            "forward_local",
            Map.of(
                    "striker", new Spec(50, Enc.U8),
                    "finishing", new Spec(56, Enc.TIMES5),
                    "pace", new Spec(92, Enc.TIMES5),
                    "concentration", new Spec(107, Enc.TIMES5)
            )
    );

    private static final LayoutVariant FORWARD_LOCAL_M5 = new LayoutVariant(
            "forward_local_m5",
            Map.of(
                    "striker", new Spec(45, Enc.U8),
                    "finishing", new Spec(51, Enc.TIMES5),
                    "pace", new Spec(87, Enc.TIMES5),
                    "concentration", new Spec(102, Enc.TIMES5)
            )
    );

    private static final LayoutVariant FORWARD_LOCAL_M6 = new LayoutVariant(
            "forward_local_m6",
            Map.of(
                    "striker", new Spec(44, Enc.U8),
                    "finishing", new Spec(50, Enc.TIMES5),
                    "pace", new Spec(86, Enc.TIMES5),
                    "concentration", new Spec(101, Enc.TIMES5)
            )
    );

    private static final LayoutVariant TOURE = new LayoutVariant(
            "toure",
            Map.of(
                    "crossing", new Spec(-963, Enc.TIMES5),
                    "dribbling", new Spec(-962, Enc.TIMES5),
                    "finishing", new Spec(-961, Enc.TIMES5),
                    "passing", new Spec(-956, Enc.TIMES5),
                    "stamina", new Spec(-926, Enc.TIMES5),
                    "pace", new Spec(-925, Enc.TIMES5),
                    "leadership", new Spec(-923, Enc.TIMES5),
                    "concentration", new Spec(-910, Enc.TIMES5)
            )
    );

    private static final LayoutVariant TOURE_P4 = new LayoutVariant(
            "toure_p4",
            Map.of(
                    "crossing", new Spec(-959, Enc.TIMES5),
                    "dribbling", new Spec(-958, Enc.TIMES5),
                    "finishing", new Spec(-957, Enc.TIMES5),
                    "passing", new Spec(-952, Enc.TIMES5),
                    "stamina", new Spec(-922, Enc.TIMES5),
                    "pace", new Spec(-921, Enc.TIMES5),
                    "leadership", new Spec(-919, Enc.TIMES5),
                    "concentration", new Spec(-906, Enc.TIMES5)
            )
    );

    private static final LayoutVariant TOURE_P5 = new LayoutVariant(
            "toure_p5",
            Map.of(
                    "crossing", new Spec(-958, Enc.TIMES5),
                    "dribbling", new Spec(-957, Enc.TIMES5),
                    "finishing", new Spec(-956, Enc.TIMES5),
                    "passing", new Spec(-951, Enc.TIMES5),
                    "stamina", new Spec(-921, Enc.TIMES5),
                    "pace", new Spec(-920, Enc.TIMES5),
                    "leadership", new Spec(-918, Enc.TIMES5),
                    "concentration", new Spec(-905, Enc.TIMES5)
            )
    );

    private static final LayoutVariant TOURE_P7 = new LayoutVariant(
            "toure_p7",
            Map.of(
                    "crossing", new Spec(-956, Enc.TIMES5),
                    "dribbling", new Spec(-955, Enc.TIMES5),
                    "finishing", new Spec(-954, Enc.TIMES5),
                    "passing", new Spec(-949, Enc.TIMES5),
                    "stamina", new Spec(-919, Enc.TIMES5),
                    "pace", new Spec(-918, Enc.TIMES5),
                    "leadership", new Spec(-916, Enc.TIMES5),
                    "concentration", new Spec(-903, Enc.TIMES5)
            )
    );

    private static final LayoutVariant ROMULO = new LayoutVariant(
            "romulo",
            Map.of(
                    "crossing", new Spec(-745, Enc.TIMES5),
                    "dribbling", new Spec(-744, Enc.TIMES5),
                    "finishing", new Spec(-743, Enc.TIMES5),
                    "leadership", new Spec(-705, Enc.TIMES5),
                    "stamina", new Spec(-706, Enc.TIMES5),
                    "pace", new Spec(-707, Enc.TIMES5),
                    "concentration", new Spec(-692, Enc.TIMES5)
            )
    );

    private GenericPlayerSubsetExtractor() {
    }

    public static void main(String[] args) throws Exception {
        Inputs inputs = Inputs.fromArgs(args);
        byte[] payload = loadPayload(inputs.save());
        List<PlayerCandidate> likelyPlayers = findLikelyPlayers(payload);

        List<SubsetRecord> extracted = new ArrayList<>();
        for (PlayerCandidate candidate : likelyPlayers) {
            FamilyDecision initialFamily = decideFamily(payload, candidate.personPair());
            List<VariantResult> variants = new ArrayList<>(variantsForFamily(payload, candidate.personPair(), initialFamily));
            variants.add(buildStandardVisibleVariant(payload, candidate.personPair()));
            VariantResult best = variants.stream()
                    .max(Comparator
                            .comparingInt(VariantResult::score)
                            .thenComparingInt(GenericPlayerSubsetExtractor::variantPriority)
                            .thenComparingInt(VariantResult::invalidCount))
                    .orElseThrow();
            best = enrichVariant(payload, candidate.personPair(), best);
            String effectiveFamily = promoteFamily(initialFamily.name(), best);
            String discoverySource = discoverySource(candidate);
            String confidence = confidenceFor(discoverySource, effectiveFamily, best);
            if (shouldRejectTailCandidate(payload, candidate.personPair(), effectiveFamily, best)) {
                continue;
            }
            extracted.add(new SubsetRecord(candidate.id(), candidate.personPair(), candidate.extraPair(), discoverySource, effectiveFamily, initialFamily.score(), confidence, best));
        }

        String json = renderJson(inputs.save(), payload.length, likelyPlayers.size(), extracted);
        if (inputs.output() == null) {
            System.out.print(json);
        } else {
            Files.writeString(inputs.output(), json, StandardCharsets.UTF_8);
            System.out.println("{\"save\": " + quote(inputs.save().toString())
                    + ", \"output\": " + quote(inputs.output().toString())
                    + ", \"likelyPlayers\": " + likelyPlayers.size()
                    + ", \"profiledPlayers\": " + extracted.size() + "}");
        }
    }

    private static List<PlayerCandidate> findLikelyPlayers(byte[] payload) {
        Map<Integer, PairBuckets> byId = new LinkedHashMap<>();
        for (int offset = 0; offset + 8 <= payload.length; offset++) {
            int left = u32le(payload, offset);
            if (left == 0 || left == -1) {
                continue;
            }
            if (u32le(payload, offset + DUP_PAIR_DISTANCE) != left) {
                continue;
            }
            PairBuckets buckets = byId.computeIfAbsent(left, ignored -> new PairBuckets());
            if (offset >= PERSON_BLOCK_MIN_OFFSET && offset < PERSON_BLOCK_MAX_OFFSET) {
                if (buckets.personPair == null) {
                    buckets.personPair = offset;
                }
            } else if (offset >= PLAYER_EXTRA_MIN_OFFSET && buckets.extraPair == null) {
                buckets.extraPair = offset;
            }
        }

        List<PlayerCandidate> players = new ArrayList<>();
        for (Map.Entry<Integer, PairBuckets> entry : byId.entrySet()) {
            PairBuckets buckets = entry.getValue();
            if (buckets.personPair == null) {
                continue;
            }
            boolean acceptedByExtra = buckets.extraPair != null
                    && hasPlayerExtraShape(payload, buckets.personPair, buckets.extraPair);
            boolean acceptedByPreamble = hasStrongPlayerPreamble(payload, buckets.personPair);
            if (!acceptedByExtra && !acceptedByPreamble) {
                continue;
            }
            players.add(new PlayerCandidate(entry.getKey(), buckets.personPair, buckets.extraPair == null ? -1 : buckets.extraPair));
        }
        players.sort(Comparator.comparingInt(PlayerCandidate::personPair));
        return collapseOverlappingCandidates(payload, players);
    }

    private static List<PlayerCandidate> collapseOverlappingCandidates(byte[] payload, List<PlayerCandidate> candidates) {
        if (candidates.isEmpty()) {
            return candidates;
        }
        List<PlayerCandidate> collapsed = new ArrayList<>();
        List<PlayerCandidate> cluster = new ArrayList<>();
        cluster.add(candidates.get(0));
        for (int i = 1; i < candidates.size(); i++) {
            PlayerCandidate next = candidates.get(i);
            PlayerCandidate last = cluster.get(cluster.size() - 1);
            if (next.personPair() - last.personPair() <= 3) {
                cluster.add(next);
                continue;
            }
            collapsed.add(bestClusterCandidate(payload, cluster));
            cluster = new ArrayList<>();
            cluster.add(next);
        }
        collapsed.add(bestClusterCandidate(payload, cluster));
        return collapsed;
    }

    private static PlayerCandidate bestClusterCandidate(byte[] payload, List<PlayerCandidate> cluster) {
        return cluster.stream()
                .max(Comparator
                        .comparingInt((PlayerCandidate candidate) -> candidateRank(payload, candidate))
                        .thenComparingInt(PlayerCandidate::personPair))
                .orElseThrow();
    }

    private static int candidateRank(byte[] payload, PlayerCandidate candidate) {
        int score = bestLocalPlayerScore(payload, candidate.personPair());
        if (hasStrongPlayerPreamble(payload, candidate.personPair())) {
            score += 100;
        }
        if (candidate.extraPair() >= 0) {
            score += signatureAt(payload, candidate.extraPair()).equals(ALT_PLAYER_SIGNATURE) ? 10 : 20;
        }
        return score;
    }

    private static VariantResult scoreVariant(byte[] payload, int personPair, LayoutVariant variant) {
        Map<String, Integer> decoded = new LinkedHashMap<>();
        int score = 0;
        int invalidCount = 0;
        for (Map.Entry<String, Spec> entry : variant.fields().entrySet()) {
            Integer value = entry.getValue().enc().decodeValue(payload, personPair + entry.getValue().delta());
            decoded.put(entry.getKey(), value);
            if (plausible(entry.getKey(), value)) {
                score++;
            } else {
                invalidCount++;
            }
        }
        score -= penalty(variant.name(), decoded);
        return new VariantResult(variant.name(), score, invalidCount, decoded);
    }

    private static VariantResult enrichVariant(byte[] payload, int personPair, VariantResult best) {
        if (best.name().startsWith("forward_local")) {
            Map<String, Integer> merged = new LinkedHashMap<>(best.decoded());
            fillForwardField(payload, personPair, merged, "striker");
            fillForwardField(payload, personPair, merged, "finishing");
            fillForwardField(payload, personPair, merged, "pace");
            fillForwardField(payload, personPair, merged, "concentration");
            return rebuildVariant(best.name(), merged);
        }
        if (best.name().equals("trauner")) {
            Map<String, Integer> merged = new LinkedHashMap<>(best.decoded());
            fillFieldFromSpecs(payload, personPair, merged, "potential_ability", traunerFieldSpecs("potential_ability"));
            fillFieldFromSpecs(payload, personPair, merged, "striker", traunerFieldSpecs("striker"));
            fillFieldFromSpecs(payload, personPair, merged, "finishing", traunerFieldSpecs("finishing"));
            fillFieldFromSpecs(payload, personPair, merged, "pace", traunerFieldSpecs("pace"));
            fillFieldFromSpecs(payload, personPair, merged, "concentration", traunerFieldSpecs("concentration"));
            fillFieldFromSpecs(payload, personPair, merged, "controversy", traunerFieldSpecs("controversy"));
            return rebuildVariant(best.name(), merged);
        }
        if (best.name().equals("smal")) {
            Map<String, Integer> merged = new LinkedHashMap<>(best.decoded());
            fillFieldFromSpecs(payload, personPair, merged, "potential_ability", smalFieldSpecs("potential_ability"));
            fillFieldFromSpecs(payload, personPair, merged, "striker", smalFieldSpecs("striker"));
            fillFieldFromSpecs(payload, personPair, merged, "finishing", smalFieldSpecs("finishing"));
            fillFieldFromSpecs(payload, personPair, merged, "pace", smalFieldSpecs("pace"));
            fillFieldFromSpecs(payload, personPair, merged, "concentration", smalFieldSpecs("concentration"));
            fillFieldFromSpecs(payload, personPair, merged, "controversy", smalFieldSpecs("controversy"));
            return rebuildVariant(best.name(), merged);
        }
        if (best.name().startsWith("toure")) {
            Map<String, Integer> merged = new LinkedHashMap<>(best.decoded());
            fillFieldFromSpecs(payload, personPair, merged, "crossing", toureFieldSpecs(best.name(), "crossing"));
            fillFieldFromSpecs(payload, personPair, merged, "dribbling", toureFieldSpecs(best.name(), "dribbling"));
            fillFieldFromSpecs(payload, personPair, merged, "finishing", toureFieldSpecs(best.name(), "finishing"));
            fillFieldFromSpecs(payload, personPair, merged, "passing", toureFieldSpecs(best.name(), "passing"));
            fillFieldFromSpecs(payload, personPair, merged, "stamina", toureFieldSpecs(best.name(), "stamina"));
            fillFieldFromSpecs(payload, personPair, merged, "pace", toureFieldSpecs(best.name(), "pace"));
            fillFieldFromSpecs(payload, personPair, merged, "leadership", toureFieldSpecs(best.name(), "leadership"));
            fillFieldFromSpecs(payload, personPair, merged, "concentration", toureFieldSpecs(best.name(), "concentration"));
            return rebuildVariant(best.name(), merged);
        }
        if (best.name().equals("romulo")) {
            Map<String, Integer> merged = new LinkedHashMap<>(best.decoded());
            fillFieldFromSpecs(payload, personPair, merged, "crossing", romuloFieldSpecs("crossing"));
            fillFieldFromSpecs(payload, personPair, merged, "dribbling", romuloFieldSpecs("dribbling"));
            fillFieldFromSpecs(payload, personPair, merged, "finishing", romuloFieldSpecs("finishing"));
            fillFieldFromSpecs(payload, personPair, merged, "leadership", romuloFieldSpecs("leadership"));
            fillFieldFromSpecs(payload, personPair, merged, "stamina", romuloFieldSpecs("stamina"));
            fillFieldFromSpecs(payload, personPair, merged, "pace", romuloFieldSpecs("pace"));
            fillFieldFromSpecs(payload, personPair, merged, "concentration", romuloFieldSpecs("concentration"));
            return rebuildVariant(best.name(), merged);
        }
        return best;
    }

    private static VariantResult rebuildVariant(String variantName, Map<String, Integer> merged) {
        int score = 0;
        int invalidCount = 0;
        for (Map.Entry<String, Integer> entry : merged.entrySet()) {
            if (plausible(entry.getKey(), entry.getValue())) {
                score++;
            } else {
                invalidCount++;
            }
        }
        score -= penalty(variantName, merged);
        return new VariantResult(variantName, score, invalidCount, merged);
    }

    private static int variantPriority(VariantResult variant) {
        return switch (variant.name()) {
            case "standard_visible" -> 100;
            case "romulo" -> 60;
            case "toure", "toure_p4", "toure_p5", "toure_p7" -> 50;
            default -> 0;
        };
    }

    private static VariantResult buildStandardVisibleVariant(byte[] payload, int personPair) {
        InferredStandardCandidate inferred = inferStandardVisibleCandidate(payload, personPair);
        if (inferred == null) {
            return new VariantResult("standard_visible", Integer.MIN_VALUE / 4, Integer.MAX_VALUE / 4, Map.of());
        }
        Map<String, Integer> decoded = new LinkedHashMap<>();
        int start = personPair + inferred.startDelta();
        int score = inferred.score();
        int invalidCount = 0;
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(STANDARD_VISIBLE_FIELDS.entrySet());
        entries.sort(Comparator.comparingInt(Map.Entry::getValue));
        for (Map.Entry<String, Integer> entry : entries) {
            int stored = payload[start + entry.getValue()] & 0xFF;
            int value = decodeStandardVisibleValue(stored, inferred.bias());
            decoded.put(entry.getKey(), value);
            if (!plausible(entry.getKey(), value)) {
                invalidCount++;
            }
        }
        return new VariantResult("standard_visible", score, invalidCount, decoded);
    }

    private static InferredStandardCandidate inferStandardVisibleCandidate(byte[] payload, int personPair) {
        InferredStandardCandidate best = null;
        for (int delta = STANDARD_SEARCH_MIN_DELTA; delta <= STANDARD_SEARCH_MAX_DELTA; delta++) {
            int start = personPair + delta;
            if (start < 0 || start + 64 > payload.length) {
                continue;
            }
            if (!hasStandardTailMarker(payload, start)) {
                continue;
            }
            for (int bias = 0; bias <= 4; bias++) {
                int plausibleCount = 0;
                int residueTarget = (5 - bias) % 5;
                int residueCount = 0;
                for (int position : STANDARD_INFERENCE_POSITIONS) {
                    int stored = payload[start + position] & 0xFF;
                    int decoded = decodeStandardVisibleValue(stored, bias);
                    if (decoded >= 1 && decoded <= 20) {
                        plausibleCount++;
                    }
                    if (stored % 5 == residueTarget) {
                        residueCount++;
                    }
                }
                InferredStandardCandidate candidate = new InferredStandardCandidate(delta, bias, plausibleCount, residueCount);
                if (best == null
                        || candidate.score() > best.score()
                        || (candidate.score() == best.score() && candidate.residueCount() > best.residueCount())
                        || (candidate.score() == best.score() && candidate.residueCount() == best.residueCount()
                        && candidate.startDelta() > best.startDelta())) {
                    best = candidate;
                }
            }
        }
        return best;
    }

    private static boolean hasStandardTailMarker(byte[] payload, int start) {
        int b60 = payload[start + 60] & 0xFF;
        int b61 = payload[start + 61] & 0xFF;
        int b62 = payload[start + 62] & 0xFF;
        int b63 = payload[start + 63] & 0xFF;
        return (b60 == 7 && b61 == 1 && b62 == 0 && b63 == 108)
                || (b60 == 7 && b61 == 237 && b62 == 0 && b63 == 233);
    }

    private static int decodeStandardVisibleValue(int stored, int bias) {
        if (stored == 0) {
            return 0;
        }
        return Math.max(1, (stored + bias) / 5);
    }

    private static void fillFieldFromSpecs(byte[] payload, int personPair, Map<String, Integer> merged, String field, List<Spec> specs) {
        if (plausible(field, merged.get(field))) {
            return;
        }
        for (Spec spec : specs) {
            Integer value = spec.enc().decodeValue(payload, personPair + spec.delta());
            if (plausible(field, value)) {
                merged.put(field, value);
                return;
            }
        }
    }

    private static void fillForwardField(byte[] payload, int personPair, Map<String, Integer> merged, String field) {
        fillFieldFromSpecs(payload, personPair, merged, field, forwardFieldSpecs(field));
    }

    private static List<Spec> forwardFieldSpecs(String field) {
        return switch (field) {
            case "striker" -> List.of(
                    new Spec(50, Enc.U8),
                    new Spec(45, Enc.U8),
                    new Spec(44, Enc.U8),
                    new Spec(40, Enc.U8),
                    new Spec(39, Enc.U8),
                    new Spec(38, Enc.U8),
                    new Spec(41, Enc.U8),
                    new Spec(46, Enc.U8),
                    new Spec(51, Enc.U8)
            );
            case "finishing" -> List.of(
                    new Spec(56, Enc.TIMES5),
                    new Spec(51, Enc.TIMES5),
                    new Spec(50, Enc.TIMES5),
                    new Spec(46, Enc.TIMES5),
                    new Spec(45, Enc.TIMES5),
                    new Spec(44, Enc.TIMES5),
                    new Spec(47, Enc.TIMES5),
                    new Spec(52, Enc.TIMES5),
                    new Spec(57, Enc.TIMES5)
            );
            case "pace" -> List.of(
                    new Spec(92, Enc.TIMES5),
                    new Spec(87, Enc.TIMES5),
                    new Spec(86, Enc.TIMES5),
                    new Spec(82, Enc.TIMES5),
                    new Spec(81, Enc.TIMES5),
                    new Spec(80, Enc.TIMES5),
                    new Spec(83, Enc.TIMES5),
                    new Spec(88, Enc.TIMES5),
                    new Spec(93, Enc.TIMES5)
            );
            case "concentration" -> List.of(
                    new Spec(107, Enc.TIMES5),
                    new Spec(102, Enc.TIMES5),
                    new Spec(101, Enc.TIMES5),
                    new Spec(97, Enc.TIMES5),
                    new Spec(96, Enc.TIMES5),
                    new Spec(95, Enc.TIMES5),
                    new Spec(98, Enc.TIMES5),
                    new Spec(103, Enc.TIMES5),
                    new Spec(108, Enc.TIMES5)
            );
            default -> List.of();
        };
    }

    private static List<Spec> traunerFieldSpecs(String field) {
        return switch (field) {
            case "potential_ability" -> List.of(
                    new Spec(-1184, Enc.U16LE),
                    new Spec(-1185, Enc.U16LE),
                    new Spec(-1183, Enc.U16LE),
                    new Spec(-1186, Enc.U16LE),
                    new Spec(-1182, Enc.U16LE),
                    new Spec(-1188, Enc.U16LE),
                    new Spec(-1180, Enc.U16LE)
            );
            case "striker" -> List.of(
                    new Spec(-1150, Enc.U8),
                    new Spec(-1151, Enc.U8),
                    new Spec(-1149, Enc.U8),
                    new Spec(-1152, Enc.U8),
                    new Spec(-1148, Enc.U8),
                    new Spec(-1154, Enc.U8),
                    new Spec(-1146, Enc.U8)
            );
            case "finishing" -> List.of(
                    new Spec(-1145, Enc.TIMES5),
                    new Spec(-1146, Enc.TIMES5),
                    new Spec(-1144, Enc.TIMES5),
                    new Spec(-1147, Enc.TIMES5),
                    new Spec(-1143, Enc.TIMES5),
                    new Spec(-1149, Enc.TIMES5),
                    new Spec(-1141, Enc.TIMES5)
            );
            case "pace" -> List.of(
                    new Spec(-1109, Enc.TIMES5),
                    new Spec(-1110, Enc.TIMES5),
                    new Spec(-1108, Enc.TIMES5),
                    new Spec(-1111, Enc.TIMES5),
                    new Spec(-1107, Enc.TIMES5),
                    new Spec(-1113, Enc.TIMES5),
                    new Spec(-1105, Enc.TIMES5)
            );
            case "concentration" -> List.of(
                    new Spec(-1094, Enc.TIMES5),
                    new Spec(-1095, Enc.TIMES5),
                    new Spec(-1093, Enc.TIMES5),
                    new Spec(-1096, Enc.TIMES5),
                    new Spec(-1092, Enc.TIMES5),
                    new Spec(-1098, Enc.TIMES5),
                    new Spec(-1090, Enc.TIMES5)
            );
            case "controversy" -> List.of(
                    new Spec(-182, Enc.U8),
                    new Spec(-183, Enc.U8),
                    new Spec(-181, Enc.U8),
                    new Spec(-184, Enc.U8),
                    new Spec(-180, Enc.U8),
                    new Spec(-186, Enc.U8),
                    new Spec(-178, Enc.U8)
            );
            default -> List.of();
        };
    }

    private static List<Spec> smalFieldSpecs(String field) {
        return switch (field) {
            case "potential_ability" -> List.of(
                    new Spec(-1077, Enc.U16LE),
                    new Spec(-1085, Enc.U16LE),
                    new Spec(-1081, Enc.U16LE),
                    new Spec(-1078, Enc.U16LE),
                    new Spec(-1076, Enc.U16LE),
                    new Spec(-1079, Enc.U16LE),
                    new Spec(-1075, Enc.U16LE)
            );
            case "striker" -> List.of(
                    new Spec(-1038, Enc.U8),
                    new Spec(-1046, Enc.U8),
                    new Spec(-1034, Enc.U8),
                    new Spec(-1039, Enc.U8),
                    new Spec(-1037, Enc.U8)
            );
            case "finishing" -> List.of(
                    new Spec(-1043, Enc.TIMES5),
                    new Spec(-1051, Enc.TIMES5),
                    new Spec(-1039, Enc.TIMES5),
                    new Spec(-1044, Enc.TIMES5),
                    new Spec(-1042, Enc.TIMES5)
            );
            case "pace" -> List.of(
                    new Spec(-1002, Enc.TIMES5),
                    new Spec(-1010, Enc.TIMES5),
                    new Spec(-998, Enc.TIMES5),
                    new Spec(-1003, Enc.TIMES5),
                    new Spec(-1001, Enc.TIMES5)
            );
            case "concentration" -> List.of(
                    new Spec(-987, Enc.TIMES5),
                    new Spec(-995, Enc.TIMES5),
                    new Spec(-983, Enc.TIMES5),
                    new Spec(-988, Enc.TIMES5),
                    new Spec(-986, Enc.TIMES5)
            );
            case "controversy" -> List.of(
                    new Spec(-255, Enc.U8),
                    new Spec(-263, Enc.U8),
                    new Spec(-251, Enc.U8),
                    new Spec(-256, Enc.U8),
                    new Spec(-254, Enc.U8)
            );
            default -> List.of();
        };
    }

    private static List<Spec> toureFieldSpecs(String variant, String field) {
        int primaryShift = switch (variant) {
            case "toure_p4" -> 4;
            case "toure_p5" -> 5;
            case "toure_p7" -> 7;
            default -> 0;
        };
        return switch (field) {
            case "crossing" -> List.of(
                    new Spec(-963 + primaryShift, Enc.TIMES5),
                    new Spec(-964 + primaryShift, Enc.TIMES5),
                    new Spec(-962 + primaryShift, Enc.TIMES5),
                    new Spec(-963, Enc.TIMES5),
                    new Spec(-958, Enc.TIMES5),
                    new Spec(-956, Enc.TIMES5)
            );
            case "dribbling" -> List.of(
                    new Spec(-962 + primaryShift, Enc.TIMES5),
                    new Spec(-963 + primaryShift, Enc.TIMES5),
                    new Spec(-961 + primaryShift, Enc.TIMES5),
                    new Spec(-962, Enc.TIMES5),
                    new Spec(-957, Enc.TIMES5),
                    new Spec(-955, Enc.TIMES5)
            );
            case "finishing" -> List.of(
                    new Spec(-961 + primaryShift, Enc.TIMES5),
                    new Spec(-962 + primaryShift, Enc.TIMES5),
                    new Spec(-960 + primaryShift, Enc.TIMES5),
                    new Spec(-961, Enc.TIMES5),
                    new Spec(-956, Enc.TIMES5),
                    new Spec(-954, Enc.TIMES5)
            );
            case "passing" -> List.of(
                    new Spec(-956 + primaryShift, Enc.TIMES5),
                    new Spec(-957 + primaryShift, Enc.TIMES5),
                    new Spec(-955 + primaryShift, Enc.TIMES5),
                    new Spec(-956, Enc.TIMES5),
                    new Spec(-951, Enc.TIMES5),
                    new Spec(-949, Enc.TIMES5)
            );
            case "stamina" -> List.of(
                    new Spec(-926 + primaryShift, Enc.TIMES5),
                    new Spec(-927 + primaryShift, Enc.TIMES5),
                    new Spec(-925 + primaryShift, Enc.TIMES5),
                    new Spec(-926, Enc.TIMES5),
                    new Spec(-921, Enc.TIMES5),
                    new Spec(-919, Enc.TIMES5)
            );
            case "pace" -> List.of(
                    new Spec(-925 + primaryShift, Enc.TIMES5),
                    new Spec(-926 + primaryShift, Enc.TIMES5),
                    new Spec(-924 + primaryShift, Enc.TIMES5),
                    new Spec(-925, Enc.TIMES5),
                    new Spec(-920, Enc.TIMES5),
                    new Spec(-918, Enc.TIMES5)
            );
            case "leadership" -> List.of(
                    new Spec(-923 + primaryShift, Enc.TIMES5),
                    new Spec(-924 + primaryShift, Enc.TIMES5),
                    new Spec(-922 + primaryShift, Enc.TIMES5),
                    new Spec(-923, Enc.TIMES5),
                    new Spec(-918, Enc.TIMES5),
                    new Spec(-916, Enc.TIMES5)
            );
            case "concentration" -> List.of(
                    new Spec(-910 + primaryShift, Enc.TIMES5),
                    new Spec(-911 + primaryShift, Enc.TIMES5),
                    new Spec(-909 + primaryShift, Enc.TIMES5),
                    new Spec(-910, Enc.TIMES5),
                    new Spec(-905, Enc.TIMES5),
                    new Spec(-903, Enc.TIMES5)
            );
            default -> List.of();
        };
    }

    private static List<Spec> romuloFieldSpecs(String field) {
        return switch (field) {
            case "crossing" -> List.of(
                    new Spec(-745, Enc.TIMES5),
                    new Spec(-746, Enc.TIMES5),
                    new Spec(-744, Enc.TIMES5)
            );
            case "dribbling" -> List.of(
                    new Spec(-744, Enc.TIMES5),
                    new Spec(-745, Enc.TIMES5),
                    new Spec(-743, Enc.TIMES5)
            );
            case "finishing" -> List.of(
                    new Spec(-743, Enc.TIMES5),
                    new Spec(-744, Enc.TIMES5),
                    new Spec(-742, Enc.TIMES5)
            );
            case "leadership" -> List.of(
                    new Spec(-705, Enc.TIMES5),
                    new Spec(-706, Enc.TIMES5),
                    new Spec(-704, Enc.TIMES5)
            );
            case "stamina" -> List.of(
                    new Spec(-706, Enc.TIMES5),
                    new Spec(-707, Enc.TIMES5),
                    new Spec(-705, Enc.TIMES5)
            );
            case "pace" -> List.of(
                    new Spec(-707, Enc.TIMES5),
                    new Spec(-706, Enc.TIMES5),
                    new Spec(-708, Enc.TIMES5)
            );
            case "concentration" -> List.of(
                    new Spec(-692, Enc.TIMES5),
                    new Spec(-693, Enc.TIMES5),
                    new Spec(-691, Enc.TIMES5)
            );
            default -> List.of();
        };
    }

    private static boolean plausible(String field, Integer value) {
        if (value == null) {
            return false;
        }
        return switch (field) {
            case "potential_ability" -> value >= 1 && value <= 200;
            case "striker", "controversy", "defensive_midfielder" -> value >= 0 && value <= 20;
            case "ambition", "versatility", "temperament" -> value >= 1 && value <= 20;
            default -> value >= 1 && value <= 20;
        };
    }

    private static List<VariantResult> variantsForFamily(byte[] payload, int personPair, FamilyDecision family) {
        return switch (family.name()) {
            case "smal_compact" -> List.of(scoreVariant(payload, personPair, SMAL));
            case "trauner_local" -> List.of(scoreVariant(payload, personPair, TRAUNER));
            case "forward_local" -> List.of(scoreVariant(payload, personPair, FORWARD_LOCAL));
            case "forward_local_m5" -> List.of(scoreVariant(payload, personPair, FORWARD_LOCAL_M5));
            case "forward_local_m6" -> List.of(scoreVariant(payload, personPair, FORWARD_LOCAL_M6));
            case "toure_compact" -> List.of(
                    scoreVariant(payload, personPair, TOURE),
                    scoreVariant(payload, personPair, TOURE_P4),
                    scoreVariant(payload, personPair, TOURE_P5),
                    scoreVariant(payload, personPair, TOURE_P7)
            );
            case "romulo_compact" -> List.of(scoreVariant(payload, personPair, ROMULO));
            case "kooistra_local" -> List.of(
                    scoreVariant(payload, personPair, KOOISTRA),
                    scoreVariant(payload, personPair, TRAUNER)
            );
            case "aidoo_relocated" -> List.of(scoreVariant(payload, personPair, AIDOO));
            default -> List.of(
                    scoreVariant(payload, personPair, FORWARD_LOCAL),
                    scoreVariant(payload, personPair, FORWARD_LOCAL_M5),
                    scoreVariant(payload, personPair, FORWARD_LOCAL_M6),
                    scoreVariant(payload, personPair, TOURE),
                    scoreVariant(payload, personPair, TOURE_P4),
                    scoreVariant(payload, personPair, TOURE_P5),
                    scoreVariant(payload, personPair, TOURE_P7),
                    scoreVariant(payload, personPair, ROMULO),
                    scoreVariant(payload, personPair, TRAUNER),
                    scoreVariant(payload, personPair, KOOISTRA),
                    scoreVariant(payload, personPair, AIDOO),
                    scoreVariant(payload, personPair, SMAL)
            );
        };
    }

    private static FamilyDecision decideFamily(byte[] payload, int personPair) {
        int compactScore = scoreCompactNegativeFamily(payload, personPair);
        int traunerScore = scoreTraunerLocalFamily(payload, personPair);
        int forwardScore = scoreForwardLocalFamily(payload, personPair);
        int forwardM5Score = scoreForwardLocalM5Family(payload, personPair);
        int forwardM6Score = scoreForwardLocalM6Family(payload, personPair);
        int toureScore = scoreToureCompactFamily(payload, personPair);
        int romuloScore = scoreRomuloCompactFamily(payload, personPair);
        int localScore = scoreLocalFamily(payload, personPair);
        int relocatedScore = scoreRelocatedFamily(payload, personPair);

        List<FamilyDecision> ranked = List.of(
                new FamilyDecision("smal_compact", compactScore),
                new FamilyDecision("trauner_local", traunerScore),
                new FamilyDecision("forward_local", forwardScore),
                new FamilyDecision("forward_local_m5", forwardM5Score),
                new FamilyDecision("forward_local_m6", forwardM6Score),
                new FamilyDecision("toure_compact", toureScore),
                new FamilyDecision("romulo_compact", romuloScore),
                new FamilyDecision("kooistra_local", localScore),
                new FamilyDecision("aidoo_relocated", relocatedScore)
        ).stream().sorted(Comparator.comparingInt(FamilyDecision::score).reversed()).toList();

        FamilyDecision best = ranked.get(0);
        FamilyDecision second = ranked.get(1);
        if (best.score() < 2 || best.score() - second.score() < FAMILY_MARGIN) {
            return new FamilyDecision("unknown", best.score());
        }
        return best;
    }

    private static int scoreForwardLocalFamily(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleAt(payload, personPair, 50, Enc.U8, "striker") ? 1 : 0;
        score += plausibleAt(payload, personPair, 56, Enc.TIMES5, "finishing") ? 2 : 0;
        score += plausibleAt(payload, personPair, 92, Enc.TIMES5, "pace") ? 2 : 0;
        score += plausibleAt(payload, personPair, 107, Enc.TIMES5, "concentration") ? 2 : 0;
        return score;
    }

    private static int scoreForwardLocalM5Family(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleAt(payload, personPair, 45, Enc.U8, "striker") ? 1 : 0;
        score += plausibleAt(payload, personPair, 51, Enc.TIMES5, "finishing") ? 2 : 0;
        score += plausibleAt(payload, personPair, 87, Enc.TIMES5, "pace") ? 2 : 0;
        score += plausibleAt(payload, personPair, 102, Enc.TIMES5, "concentration") ? 2 : 0;
        return score;
    }

    private static int scoreForwardLocalM6Family(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleAt(payload, personPair, 44, Enc.U8, "striker") ? 1 : 0;
        score += plausibleAt(payload, personPair, 50, Enc.TIMES5, "finishing") ? 2 : 0;
        score += plausibleAt(payload, personPair, 86, Enc.TIMES5, "pace") ? 2 : 0;
        score += plausibleAt(payload, personPair, 101, Enc.TIMES5, "concentration") ? 2 : 0;
        return score;
    }

    private static int scoreToureCompactFamily(byte[] payload, int personPair) {
        return Math.max(
                scoreToureCompactFamily(payload, personPair, 0),
                Math.max(
                        scoreToureCompactFamily(payload, personPair, 4),
                        Math.max(
                                scoreToureCompactFamily(payload, personPair, 5),
                                scoreToureCompactFamily(payload, personPair, 7)
                        )
                )
        );
    }

    private static int scoreToureCompactFamily(byte[] payload, int personPair, int shift) {
        int score = 0;
        score += plausibleAt(payload, personPair, -963 + shift, Enc.TIMES5, "crossing") ? 1 : 0;
        score += plausibleAt(payload, personPair, -962 + shift, Enc.TIMES5, "dribbling") ? 2 : 0;
        score += plausibleAt(payload, personPair, -961 + shift, Enc.TIMES5, "finishing") ? 1 : 0;
        score += plausibleAt(payload, personPair, -956 + shift, Enc.TIMES5, "passing") ? 1 : 0;
        score += plausibleAt(payload, personPair, -926 + shift, Enc.TIMES5, "stamina") ? 1 : 0;
        score += plausibleAt(payload, personPair, -925 + shift, Enc.TIMES5, "pace") ? 2 : 0;
        score += plausibleAt(payload, personPair, -923 + shift, Enc.TIMES5, "leadership") ? 1 : 0;
        score += plausibleAt(payload, personPair, -910 + shift, Enc.TIMES5, "concentration") ? 2 : 0;
        return score;
    }

    private static int scoreRomuloCompactFamily(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleAt(payload, personPair, -745, Enc.TIMES5, "crossing") ? 1 : 0;
        score += plausibleAt(payload, personPair, -744, Enc.TIMES5, "dribbling") ? 2 : 0;
        score += plausibleAt(payload, personPair, -743, Enc.TIMES5, "finishing") ? 2 : 0;
        score += plausibleAt(payload, personPair, -705, Enc.TIMES5, "leadership") ? 1 : 0;
        score += plausibleAt(payload, personPair, -706, Enc.TIMES5, "stamina") ? 2 : 0;
        score += plausibleAt(payload, personPair, -707, Enc.TIMES5, "pace") ? 2 : 0;
        score += plausibleAt(payload, personPair, -692, Enc.TIMES5, "concentration") ? 2 : 0;
        return score;
    }

    private static int scoreTraunerLocalFamily(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleAt(payload, personPair, -1192 + 8, Enc.U16LE, "potential_ability") ? 2 : 0;
        score += plausibleAt(payload, personPair, -1160 + 10, Enc.U8, "striker") ? 2 : 0;
        score += plausibleAt(payload, personPair, -1145, Enc.TIMES5, "finishing") ? 1 : 0;
        score += plausibleAt(payload, personPair, -1145 + 36, Enc.TIMES5, "pace") ? 1 : 0;
        score += plausibleAt(payload, personPair, -1145 + 51, Enc.TIMES5, "concentration") ? 1 : 0;
        score += plausibleAt(payload, personPair, -1145 + 47, Enc.TIMES5, "versatility") ? 1 : 0;
        score += plausibleAt(payload, personPair, -236 + 54, Enc.U8, "controversy") ? 1 : 0;
        score += plausibleAt(payload, personPair, -236 + 53, Enc.U8, "temperament") ? 1 : 0;
        return score;
    }

    private static int scoreCompactNegativeFamily(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleAt(payload, personPair, -1077, Enc.U16LE, "potential_ability") ? 2 : 0;
        score += plausibleAt(payload, personPair, -1043, Enc.TIMES5, "finishing") ? 1 : 0;
        score += plausibleAt(payload, personPair, -1038, Enc.U8, "striker") ? 1 : 0;
        score += plausibleAt(payload, personPair, -1002, Enc.TIMES5, "pace") ? 1 : 0;
        score += plausibleAt(payload, personPair, -987, Enc.TIMES5, "concentration") ? 1 : 0;
        score += plausibleAt(payload, personPair, -255, Enc.U8, "controversy") ? 1 : 0;
        return score;
    }

    private static int scoreLocalFamily(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleAt(payload, personPair, -713, Enc.U8, "defensive_midfielder") ? 2 : 0;
        score += plausibleAt(payload, personPair, -702, Enc.TIMES5_PLUS_ONE_FLOOR, "dribbling") ? 1 : 0;
        score += plausibleAt(payload, personPair, -698, Enc.TIMES5_PLUS_ONE_FLOOR, "marking") ? 1 : 0;
        score += plausibleAt(payload, personPair, -667, Enc.TIMES5_PLUS_ONE_FLOOR, "strength") ? 1 : 0;
        score += plausibleAt(payload, personPair, -666, Enc.TIMES5_PLUS_ONE_FLOOR, "stamina") ? 1 : 0;
        score += plausibleAt(payload, personPair, -663, Enc.TIMES5_PLUS_ONE_FLOOR, "leadership") ? 1 : 0;
        score += plausibleAt(payload, personPair, -650, Enc.TIMES5_PLUS_ONE_FLOOR, "concentration") ? 1 : 0;
        score += plausibleAt(payload, personPair, -126, Enc.U8, "ambition") ? 1 : 0;
        return score;
    }

    private static int scoreRelocatedFamily(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleAt(payload, personPair, -1162, Enc.U8, "defensive_midfielder") ? 2 : 0;
        score += plausibleAt(payload, personPair, -17407, Enc.TIMES5, "dribbling") ? 1 : 0;
        score += plausibleAt(payload, personPair, -9400, Enc.TIMES5, "marking") ? 1 : 0;
        score += plausibleAt(payload, personPair, -6978, Enc.TIMES5, "stamina") ? 1 : 0;
        score += plausibleAt(payload, personPair, 8163, Enc.U8, "ambition") ? 1 : 0;
        score += plausibleAt(payload, personPair, 10393, Enc.TIMES5, "leadership") ? 1 : 0;
        score += plausibleAt(payload, personPair, 10401, Enc.TIMES5, "concentration") ? 1 : 0;
        return score;
    }

    private static boolean plausibleAt(byte[] payload, int personPair, int delta, Enc enc, String field) {
        int offset = personPair + delta;
        if (offset < 0 || offset >= payload.length) {
            return false;
        }
        if (enc == Enc.U16LE && offset + 1 >= payload.length) {
            return false;
        }
        Integer value = enc.decodeValue(payload, offset);
        return plausible(field, value);
    }

    private static int penalty(String variant, Map<String, Integer> decoded) {
        int penalty = 0;
        if (variant.equals("kooistra")) {
            penalty += rangePenalty(decoded.get("defensive_midfielder"), 0, 20);
            penalty += rangePenalty(decoded.get("ambition"), 1, 20);
            penalty += rangePenalty(decoded.get("concentration"), 1, 20);
            penalty += rangePenalty(decoded.get("leadership"), 1, 20);
            penalty += rangePenalty(decoded.get("dribbling"), 1, 20);
            penalty += rangePenalty(decoded.get("marking"), 1, 20);
            penalty += rangePenalty(decoded.get("stamina"), 1, 20);
            penalty += rangePenalty(decoded.get("strength"), 1, 20);
        } else if (variant.equals("smal")) {
            penalty += rangePenalty(decoded.get("striker"), 0, 20);
            penalty += rangePenalty(decoded.get("controversy"), 0, 20);
            penalty += rangePenalty(decoded.get("finishing"), 1, 20);
            penalty += rangePenalty(decoded.get("pace"), 1, 20);
            penalty += rangePenalty(decoded.get("concentration"), 1, 20);
            penalty += rangePenalty(decoded.get("potential_ability"), 1, 200);
        } else if (variant.equals("aidoo")) {
            penalty += rangePenalty(decoded.get("defensive_midfielder"), 0, 20);
            penalty += rangePenalty(decoded.get("ambition"), 1, 20);
            penalty += rangePenalty(decoded.get("leadership"), 1, 20);
            penalty += rangePenalty(decoded.get("concentration"), 1, 20);
            penalty += rangePenalty(decoded.get("marking"), 1, 20);
            penalty += rangePenalty(decoded.get("dribbling"), 1, 20);
            penalty += rangePenalty(decoded.get("stamina"), 1, 20);
        } else if (variant.equals("trauner")) {
            penalty += rangePenalty(decoded.get("striker"), 0, 20);
            penalty += rangePenalty(decoded.get("controversy"), 0, 20);
            penalty += rangePenalty(decoded.get("finishing"), 1, 20);
            penalty += rangePenalty(decoded.get("pace"), 1, 20);
            penalty += rangePenalty(decoded.get("concentration"), 1, 20);
            penalty += rangePenalty(decoded.get("potential_ability"), 1, 200);
        } else if (variant.equals("toure")) {
            penalty += rangePenalty(decoded.get("crossing"), 1, 20);
            penalty += rangePenalty(decoded.get("dribbling"), 1, 20);
            penalty += rangePenalty(decoded.get("finishing"), 1, 20);
            penalty += rangePenalty(decoded.get("passing"), 1, 20);
            penalty += rangePenalty(decoded.get("stamina"), 1, 20);
            penalty += rangePenalty(decoded.get("pace"), 1, 20);
            penalty += rangePenalty(decoded.get("leadership"), 1, 20);
            penalty += rangePenalty(decoded.get("concentration"), 1, 20);
        } else if (variant.equals("romulo")) {
            penalty += rangePenalty(decoded.get("crossing"), 1, 20);
            penalty += rangePenalty(decoded.get("dribbling"), 1, 20);
            penalty += rangePenalty(decoded.get("finishing"), 1, 20);
            penalty += rangePenalty(decoded.get("leadership"), 1, 20);
            penalty += rangePenalty(decoded.get("stamina"), 1, 20);
            penalty += rangePenalty(decoded.get("pace"), 1, 20);
            penalty += rangePenalty(decoded.get("concentration"), 1, 20);
        }
        return penalty;
    }

    private static int rangePenalty(Integer value, int min, int max) {
        if (value == null) {
            return 0;
        }
        return (value < min || value > max) ? 1 : 0;
    }

    private static int minAcceptableScore(String family, String variant) {
        if (family.equals("standard_visible") || variant.equals("standard_visible")) {
            return 30;
        }
        if (family.equals("smal_compact") || variant.equals("smal")) {
            return 3;
        }
        return MIN_ACCEPTABLE_SCORE;
    }

    private static String confidenceFor(String discoverySource, String family, VariantResult best) {
        int minScore = minAcceptableScore(family, best.name());
        if (discoverySource.equals("boundary_only")) {
            if (family.equals("unknown")) {
                return "very_low";
            }
            if (best.score() >= minScore && best.invalidCount() == 0
                    && (family.equals("forward_local")
                    || family.equals("forward_local_m5")
                    || family.equals("forward_local_m6"))) {
                return "medium";
            }
            if (best.score() >= Math.max(2, minScore - 1)) {
                return "low";
            }
            return "very_low";
        }
        if (!family.equals("unknown")
                && best.invalidCount() == 0
                && best.score() >= minScore + 1) {
            return "high";
        }
        if (best.score() >= minScore && best.invalidCount() <= 1) {
            return "medium";
        }
        if (best.score() >= Math.max(2, minScore - 1)) {
            return "low";
        }
        return "very_low";
    }

    private static String promoteFamily(String family, VariantResult best) {
        if (best.name().equals("standard_visible") && best.score() >= 30 && best.invalidCount() == 0) {
            return "standard_visible";
        }
        if (!family.equals("unknown")) {
            return family;
        }
        if (best.name().equals("smal") && best.score() >= 2 && best.invalidCount() <= 3) {
            return "smal_compact";
        }
        if (best.name().equals("trauner") && best.score() >= 3 && best.invalidCount() <= 2) {
            return "trauner_local";
        }
        if (best.name().equals("forward_local") && best.score() >= 2 && best.invalidCount() <= 2) {
            return "forward_local";
        }
        if (best.name().equals("forward_local_m5") && best.score() >= 2 && best.invalidCount() <= 2) {
            return "forward_local_m5";
        }
        if (best.name().equals("forward_local_m6") && best.score() >= 2 && best.invalidCount() <= 2) {
            return "forward_local_m6";
        }
        if (best.name().startsWith("toure") && best.score() >= 6 && best.invalidCount() <= 2) {
            return "toure_compact";
        }
        if (best.name().equals("romulo") && best.score() >= 7 && best.invalidCount() <= 1) {
            return "romulo_compact";
        }
        if (best.name().equals("aidoo") && best.score() >= 4 && best.invalidCount() <= 2) {
            return "aidoo_relocated";
        }
        if (best.name().equals("kooistra") && best.score() >= 4 && best.invalidCount() <= 2) {
            return "kooistra_local";
        }
        return family;
    }

    private static String renderJson(Path save, int payloadSize, int likelyPlayers, List<SubsetRecord> extracted) {
        StringBuilder json = new StringBuilder(1_000_000);
        long highConfidence = extracted.stream().filter(record -> record.confidence().equals("high")).count();
        long mediumConfidence = extracted.stream().filter(record -> record.confidence().equals("medium")).count();
        long lowConfidence = extracted.stream().filter(record -> record.confidence().equals("low")).count();
        long veryLowConfidence = extracted.stream().filter(record -> record.confidence().equals("very_low")).count();
        json.append("{\n");
        appendField(json, "save", quote(save.toString()), true);
        appendField(json, "payloadSize", Integer.toString(payloadSize), true);
        appendField(json, "likelyPlayerCount", Integer.toString(likelyPlayers), true);
        appendField(json, "profiledPlayerCount", Integer.toString(extracted.size()), true);
        appendField(json, "highConfidenceCount", Long.toString(highConfidence), true);
        appendField(json, "mediumConfidenceCount", Long.toString(mediumConfidence), true);
        appendField(json, "lowConfidenceCount", Long.toString(lowConfidence), true);
        appendField(json, "veryLowConfidenceCount", Long.toString(veryLowConfidence), true);
        json.append("  \"players\": [\n");
        for (int i = 0; i < extracted.size(); i++) {
            SubsetRecord record = extracted.get(i);
            json.append("    {\n");
            appendNestedField(json, "playerId", Integer.toUnsignedString(record.id()), true);
            appendNestedField(json, "personPairOffset", Integer.toString(record.personPair()), true);
            appendNestedField(json, "extraPairOffset", Integer.toString(record.extraPair()), true);
            appendNestedField(json, "discoverySource", quote(record.discoverySource()), true);
            appendNestedField(json, "family", quote(record.family()), true);
            appendNestedField(json, "familyScore", Integer.toString(record.familyScore()), true);
            appendNestedField(json, "confidence", quote(record.confidence()), true);
            appendNestedField(json, "layoutVariant", quote(record.variant().name()), true);
            appendNestedField(json, "layoutScore", Integer.toString(record.variant().score()), true);
            appendNestedField(json, "invalidFieldCount", Integer.toString(record.variant().invalidCount()), true);
            json.append("      \"fields\": {\n");
            int rendered = 0;
            for (Map.Entry<String, Integer> field : record.variant().decoded().entrySet()) {
                appendDeepField(json, field.getKey(), field.getValue() == null ? "null" : Integer.toString(field.getValue()), rendered + 1 < record.variant().decoded().size());
                rendered++;
            }
            json.append("      }\n");
            json.append("    }");
            if (i + 1 < extracted.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n}\n");
        return json.toString();
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

    private static int u32le(byte[] block, int offset) {
        return (block[offset] & 0xFF)
                | ((block[offset + 1] & 0xFF) << 8)
                | ((block[offset + 2] & 0xFF) << 16)
                | ((block[offset + 3] & 0xFF) << 24);
    }

    private static boolean hasPlayerExtraShape(byte[] payload, int personPair, int extraPair) {
        if (extraPair < 32 || extraPair + 80 >= payload.length) {
            return false;
        }
        boolean primary = payload[extraPair + 8] == 'y'
                && payload[extraPair + 9] == 't'
                && payload[extraPair + 10] == 'r'
                && payload[extraPair + 11] == 'p'
                && payload[extraPair + 34] == 'y'
                && payload[extraPair + 35] == 't'
                && payload[extraPair + 36] == 'g'
                && payload[extraPair + 37] == 'h'
                && payload[extraPair + 51] == 't'
                && payload[extraPair + 52] == 'a'
                && payload[extraPair + 53] == 'n'
                && payload[extraPair + 54] == 'N'
                && payload[extraPair + 65] == 's'
                && payload[extraPair + 66] == 'r'
                && payload[extraPair + 67] == 'e'
                && payload[extraPair + 68] == 'v'
                && payload[extraPair + 73] == 'C'
                && payload[extraPair + 74] == 'A'
                && payload[extraPair + 75] == 'p'
                && payload[extraPair + 76] == 'U';
        if (primary) {
            return true;
        }
        return signatureAt(payload, extraPair).equals(ALT_PLAYER_SIGNATURE);
    }

    private static boolean hasStrongPlayerPreamble(byte[] payload, int personPair) {
        int start = personPair - 12;
        if (start < 0 || personPair + 8 > payload.length) {
            return false;
        }
        return (payload[start] == 0x00 || payload[start] == 0x01)
                && payload[start + 1] == 0x02
                && payload[start + 2] == 0x40
                && (payload[start + 3] == 0x10 || payload[start + 3] == 0x18)
                && (payload[start + 4] == 0x04 || payload[start + 4] == 0x05)
                && payload[start + 5] == 0x00
                && payload[start + 6] == 0x00
                && payload[start + 7] == 0x00;
    }

    private static boolean hasValidPersonPreamble(byte[] payload, int personPair) {
        int start = personPair - 12;
        if (start < 0 || personPair + 8 > payload.length) {
            return false;
        }
        return (payload[start] == 0x00 || payload[start] == 0x01)
                && payload[start + 1] == 0x02
                && (payload[start + 2] == 0x00 || payload[start + 2] == 0x40)
                && (payload[start + 3] == 0x10 || payload[start + 3] == 0x18)
                && (payload[start + 4] == 0x04 || payload[start + 4] == 0x05)
                && payload[start + 5] == 0x00
                && payload[start + 6] == 0x00
                && payload[start + 7] == 0x00;
    }

    private static boolean shouldRejectTailCandidate(byte[] payload, int personPair, String family, VariantResult variant) {
        if (family.equals("unknown")
                && variant.name().equals("forward_local_m5")
                && variant.score() <= 1
                && variant.invalidCount() >= 3) {
            return true;
        }
        if (family.equals("unknown")
                && variant.name().startsWith("toure")
                && variant.score() <= 3
                && variant.invalidCount() >= 5) {
            return true;
        }
        int start = personPair - 12;
        if (family.equals("unknown")
                && variant.name().equals("standard_visible")
                && start >= 0
                && start + 8 <= payload.length
                && payload[start] == (byte) 0xFF
                && payload[start + 1] == (byte) 0xFF
                && payload[start + 2] == (byte) 0xFF
                && payload[start + 3] == (byte) 0xFF
                && payload[start + 4] == (byte) 0xFF
                && payload[start + 5] == (byte) 0xFF
                && payload[start + 6] == (byte) 0xFF
                && payload[start + 7] == (byte) 0xFF) {
            return true;
        }
        if (family.equals("unknown")
                && variant.name().equals("standard_visible")
                && start >= 0
                && start + 8 <= payload.length
                && payload[start] == 0x00
                && payload[start + 1] == 0x00
                && payload[start + 2] == (byte) 0xFF
                && payload[start + 3] == (byte) 0xFF
                && payload[start + 4] == (byte) 0xFF
                && payload[start + 5] == (byte) 0xFF
                && payload[start + 6] == (byte) 0xFF
                && payload[start + 7] == (byte) 0xFF) {
            return true;
        }
        if (family.equals("unknown")
                && variant.name().equals("standard_visible")
                && start >= 0
                && start + 8 <= payload.length
                && payload[start] == 0x00
                && payload[start + 1] == 0x00
                && payload[start + 2] == 0x40
                && payload[start + 3] == 0x00
                && payload[start + 4] == 0x04
                && payload[start + 5] == 0x00
                && payload[start + 6] == 0x00
                && payload[start + 7] == 0x00) {
            return true;
        }
        return family.equals("unknown")
                && variant.name().equals("standard_visible")
                && variant.score() <= 17
                && variant.invalidCount() >= 18
                && !hasValidPersonPreamble(payload, personPair);
    }

    private static int bestLocalPlayerScore(byte[] payload, int personPair) {
        return Math.max(
                Math.max(scoreForward(payload, personPair, 0), scoreForward(payload, personPair, -5)),
                Math.max(scoreForward(payload, personPair, -6), scoreKooistraDiscovery(payload, personPair))
        );
    }

    private static int scoreForward(byte[] payload, int personPair, int shift) {
        int score = 0;
        score += plausibleU8Discovery(payload, personPair + 50 + shift, 0, 20) ? 1 : 0;
        score += plausibleTimes5Discovery(payload, personPair + 56 + shift) ? 1 : 0;
        score += plausibleTimes5Discovery(payload, personPair + 92 + shift) ? 1 : 0;
        score += plausibleTimes5Discovery(payload, personPair + 107 + shift) ? 1 : 0;
        return score;
    }

    private static int scoreKooistraDiscovery(byte[] payload, int personPair) {
        int score = 0;
        score += plausibleU8Discovery(payload, personPair - 713, 0, 20) ? 1 : 0;
        score += plausibleTimes5PlusOneDiscovery(payload, personPair - 702) ? 1 : 0;
        score += plausibleTimes5PlusOneDiscovery(payload, personPair - 698) ? 1 : 0;
        score += plausibleTimes5PlusOneDiscovery(payload, personPair - 663) ? 1 : 0;
        score += plausibleTimes5PlusOneDiscovery(payload, personPair - 650) ? 1 : 0;
        return score;
    }

    private static boolean plausibleU8Discovery(byte[] payload, int offset, int min, int max) {
        if (offset < 0 || offset >= payload.length) {
            return false;
        }
        int value = payload[offset] & 0xFF;
        return value >= min && value <= max;
    }

    private static boolean plausibleTimes5Discovery(byte[] payload, int offset) {
        if (offset < 0 || offset >= payload.length) {
            return false;
        }
        int stored = payload[offset] & 0xFF;
        return stored % 5 == 0 && stored >= 5 && stored <= 100;
    }

    private static boolean plausibleTimes5PlusOneDiscovery(byte[] payload, int offset) {
        if (offset < 0 || offset >= payload.length) {
            return false;
        }
        int stored = payload[offset] & 0xFF;
        return stored >= 1 && stored <= 100;
    }

    private static String signatureAt(byte[] payload, int extraPair) {
        return ascii(payload, extraPair + 8, 4) + "|"
                + ascii(payload, extraPair + 34, 4) + "|"
                + ascii(payload, extraPair + 51, 4) + "|"
                + ascii(payload, extraPair + 65, 4) + "|"
                + ascii(payload, extraPair + 73, 4);
    }

    private static String ascii(byte[] payload, int offset, int length) {
        if (offset < 0 || offset + length > payload.length) {
            return "";
        }
        StringBuilder out = new StringBuilder(length);
        for (int i = offset; i < offset + length; i++) {
            int value = payload[i] & 0xFF;
            out.append(value >= 32 && value <= 126 ? (char) value : '.');
        }
        return out.toString();
    }

    private static void appendField(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("  ").append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void appendNestedField(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("      ").append(quote(name)).append(": ").append(value);
        if (trailingComma) {
            json.append(',');
        }
        json.append('\n');
    }

    private static void appendDeepField(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append("        ").append(quote(name)).append(": ").append(value);
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

    private record Inputs(Path save, Path output) {
        private static Inputs fromArgs(String[] args) {
            if (args.length == 2) {
                return new Inputs(Path.of(args[0]), Path.of(args[1]));
            }
            if (args.length == 1) {
                return new Inputs(Path.of(args[0]), null);
            }
            return new Inputs(Path.of("games/Feyenoord_after.fm"), null);
        }
    }

    private record PlayerCandidate(int id, int personPair, int extraPair) {
    }

    private static String discoverySource(PlayerCandidate candidate) {
        return candidate.extraPair() >= 0 ? "indexed" : "boundary_only";
    }

    private static final class PairBuckets {
        private Integer personPair;
        private Integer extraPair;
    }

    private record LayoutVariant(String name, Map<String, Spec> fields) {
    }

    private record Spec(int delta, Enc enc) {
    }

    private record VariantResult(String name, int score, int invalidCount, Map<String, Integer> decoded) {
    }

    private record SubsetRecord(int id, int personPair, int extraPair, String discoverySource, String family, int familyScore, String confidence, VariantResult variant) {
    }

    private record FamilyDecision(String name, int score) {
    }

    private record InferredStandardCandidate(int startDelta, int bias, int score, int residueCount) {
    }

    private enum Enc {
        U8 {
            @Override
            Integer decodeValue(byte[] payload, int offset) {
                return payload[offset] & 0xFF;
            }
        },
        TIMES5 {
            @Override
            Integer decodeValue(byte[] payload, int offset) {
                int stored = payload[offset] & 0xFF;
                return stored % 5 == 0 ? stored / 5 : null;
            }
        },
        TIMES5_PLUS_ONE_FLOOR {
            @Override
            Integer decodeValue(byte[] payload, int offset) {
                int stored = payload[offset] & 0xFF;
                return (stored + 1) / 5;
            }
        },
        U16LE {
            @Override
            Integer decodeValue(byte[] payload, int offset) {
                return (payload[offset] & 0xFF) | ((payload[offset + 1] & 0xFF) << 8);
            }
        };

        abstract Integer decodeValue(byte[] payload, int offset);
    }
}
