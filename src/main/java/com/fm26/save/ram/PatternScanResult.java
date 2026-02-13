package com.fm26.save.ram;

import java.util.List;

public record PatternScanResult(
        int pid,
        String processName,
        String command,
        List<Integer> pattern,
        int baseIndex,
        List<PatternScanHit> hits,
        List<String> warnings
) {
}
