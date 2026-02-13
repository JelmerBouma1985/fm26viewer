package com.fm26.save.ram;

public record RunningProcess(
        int pid,
        String name,
        String command
) {
}
