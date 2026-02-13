package com.fm26.save.ram;

import java.util.List;

public record RamScanResult(
        int pid,
        String processName,
        String command,
        String query,
        int scannedRegions,
        List<PlayerMemoryHit> hits,
        List<String> warnings
) {
}
