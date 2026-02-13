package com.fm26.save.ram;

import java.util.List;

public record PlayerPointerReference(
        long address,
        String addressHex,
        String region,
        List<Integer> nearbyInt32Candidates,
        List<Integer> nearbyAttributeBytes,
        List<String> nearbyStrings
) {
}
