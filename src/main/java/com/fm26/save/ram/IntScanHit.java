package com.fm26.save.ram;

import java.util.List;

public record IntScanHit(
        long address,
        String addressHex,
        String region,
        int value,
        String contextHex,
        List<PlayerPointerReference> pointerReferences
) {
}
