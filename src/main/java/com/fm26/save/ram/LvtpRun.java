package com.fm26.save.ram;

import java.util.List;

public record LvtpRun(
        long startAddress,
        String startHex,
        String region,
        int recordCount,
        List<LvtpRecord> records
) {
}

