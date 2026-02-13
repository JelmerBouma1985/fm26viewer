package com.fm26.save.ram;

public record MemoryDump(
        int pid,
        long address,
        String addressHex,
        int size,
        String base64,
        String hexPreview
) {
}
