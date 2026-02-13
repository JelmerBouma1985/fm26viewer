package com.fm26.save.ram;

import java.util.List;

public record LvtpRecord(
        int id,
        String idHex,
        List<Integer> values,
        int value
) {
}

