package com.fm26.save.ram;

public record BagScanHit(
        long windowStartAddress,
        String windowStartHex,
        String region,
        String encoding,
        int elementBytes,
        int windowBytes
) {
}

