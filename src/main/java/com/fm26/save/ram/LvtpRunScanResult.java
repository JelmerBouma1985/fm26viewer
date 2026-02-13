package com.fm26.save.ram;

import java.util.List;

public record LvtpRunScanResult(
        int pid,
        String processName,
        String command,
        int scannedRegions,
        int minRunRecords,
        List<LvtpRun> runs,
        List<String> warnings
) {
}

