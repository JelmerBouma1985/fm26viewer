package com.fm26.save.ram;

import java.util.List;

public record PointerScanResult(
        int pid,
        String processName,
        String command,
        long targetAddress,
        String targetAddressHex,
        int scannedRegions,
        List<PlayerPointerReference> references,
        List<String> warnings
) {
}

