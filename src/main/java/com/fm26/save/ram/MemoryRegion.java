package com.fm26.save.ram;

public record MemoryRegion(
        long startAddress,
        long endAddress,
        String permissions,
        String path
) {
    public boolean readable() {
        return permissions != null && !permissions.isEmpty() && permissions.charAt(0) == 'r';
    }

    public boolean executable() {
        return permissions != null && permissions.indexOf('x') >= 0;
    }

    public long size() {
        return endAddress - startAddress;
    }

    public boolean anonymousWritable() {
        String regionPath = path == null ? "" : path.trim();
        boolean anonymous = regionPath.isEmpty() || regionPath.equals("[anon]") || regionPath.equals("[heap]") || regionPath.equals("[stack]");
        boolean writable = permissions != null && permissions.length() >= 2 && permissions.charAt(0) == 'r' && permissions.charAt(1) == 'w';
        return anonymous && writable;
    }

    public String shortLabel() {
        String regionPath = (path == null || path.isBlank()) ? "[anon]" : path;
        return String.format("0x%016X-0x%016X %s %s", startAddress, endAddress, permissions, regionPath);
    }
}
