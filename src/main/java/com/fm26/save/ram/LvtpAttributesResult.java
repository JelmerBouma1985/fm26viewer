package com.fm26.save.ram;

import java.util.Map;

public record LvtpAttributesResult(
        int pid,
        String processName,
        String command,
        String lvtpRunStartHex,
        String region,
        int recordCount,
        Map<Integer, Integer> rawById,
        Map<String, Integer> attributes
) {
}

