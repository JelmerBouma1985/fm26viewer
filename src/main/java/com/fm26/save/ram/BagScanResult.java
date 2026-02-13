package com.fm26.save.ram;

import java.util.List;

public record BagScanResult(
        int pid,
        String processName,
        String command,
        List<Integer> bag,
        int windowBytes,
        int stepBytes,
        List<BagScanHit> hits,
        List<String> warnings
) {
}

