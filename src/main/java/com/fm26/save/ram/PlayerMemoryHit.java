package com.fm26.save.ram;

public record PlayerMemoryHit(
        long address,
        String addressHex,
        String region,
        String contextAscii,
        String contextHex,
        PlayerMemoryAnalysis analysis
) {
}
