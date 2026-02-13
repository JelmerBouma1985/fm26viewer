package com.fm26.save.ram;

import java.util.List;

public record PlayerIdReference(
        int idValue,
        long address,
        String addressHex,
        String region,
        int attributeScore,
        String attributeEncoding,
        int attributeMin,
        int attributeMax,
        int attributeUniqueCount,
        int attributeBlock36Score,
        String attributeBlock36Encoding,
        int attributeBlock36Offset,
        List<Integer> attributeValues36,
        java.util.Map<String, Integer> attributes,
        List<Integer> nearbyAttributeBytes,
        List<Integer> nearbyInt32Candidates,
        List<String> nearbyStrings
) {
}
