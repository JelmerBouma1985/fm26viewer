package com.fm26.save.ram;

public record MemoryDumpFile(
        int pid,
        long address,
        String addressHex,
        int size,
        String path,
        String sha256
) {
}
