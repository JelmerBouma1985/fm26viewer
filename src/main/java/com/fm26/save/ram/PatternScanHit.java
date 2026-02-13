package com.fm26.save.ram;

import java.util.List;
import java.util.Map;

public record PatternScanHit(
        long matchAddress,
        String matchAddressHex,
        String region,
        String encoding,
        int stride,
        int baseIndex,
        long blockStartAddress,
        String blockStartAddressHex,
        List<Integer> attributeValues36,
        Map<String, Integer> attributes
) {
}
