package com.fm26.save.ram;

import java.util.List;

public record PlayerMemoryAnalysis(
        String hitType,
        List<String> nearbyStrings,
        List<Integer> nearbyInt32Candidates,
        List<Integer> nearbyAttributeBytes,
        List<PlayerPointerReference> pointerReferences,
        List<PlayerIdReference> idReferences
) {
}
