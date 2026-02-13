package com.fm26.save.ram;

import java.util.List;

public record IntScanResult(
        int pid,
        String processName,
        String command,
        int value,
        int scannedRegions,
        List<IntScanHit> hits,
        List<String> warnings
) {
}

