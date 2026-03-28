package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class ContractSignatureProbe {

    private static final int FMF_ZSTD_OFFSET = 26;

    private ContractSignatureProbe() {
    }

    public static void main(String[] args) throws Exception {
        byte[] base = loadPayload(Path.of("games/Feyenoord_after.fm"));
        Map<String, Anchor> anchors = new LinkedHashMap<>();
        anchors.put("trauner_primary", new Anchor(66_583_225, -373, -318));
        anchors.put("smal_primary", new Anchor(67_755_429, -435, -380));
        anchors.put("modric_primary", new Anchor(65_460_522, -690, -635));
        anchors.put("pablo_secondary", new Anchor(69_765_171, -400, -628));

        for (Map.Entry<String, Anchor> entry : anchors.entrySet()) {
            String name = entry.getKey();
            Anchor a = entry.getValue();
            System.out.println("## " + name);
            dump(base, a.pair() + a.dateRel() - 32, 96);
            System.out.println("-- salary band");
            dump(base, a.pair() + a.salaryRel() - 32, 96);
        }
    }

    private static void dump(byte[] payload, int start, int length) {
        int end = Math.min(payload.length, start + length);
        for (int off = start; off < end; off += 16) {
            System.out.println(off + " " + hex(payload, off, Math.min(16, end - off)));
        }
    }

    private static String hex(byte[] payload, int offset, int length) {
        StringBuilder out = new StringBuilder(length * 3);
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                out.append(' ');
            }
            out.append(String.format(Locale.ROOT, "%02x", payload[offset + i] & 0xFF));
        }
        return out.toString();
    }

    private static byte[] loadPayload(Path path) throws IOException {
        if (!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".fm")) {
            return Files.readAllBytes(path);
        }
        try (InputStream raw = new BufferedInputStream(Files.newInputStream(path));
             InputStream skipped = skipFully(raw, FMF_ZSTD_OFFSET);
             ZstdInputStream zstd = new ZstdInputStream(skipped)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            while (true) {
                try {
                    int read = zstd.read(buffer);
                    if (read < 0) {
                        break;
                    }
                    output.write(buffer, 0, read);
                } catch (ZstdIOException exception) {
                    if (output.size() > 0 && exception.getMessage() != null
                            && exception.getMessage().contains("Unknown frame descriptor")) {
                        break;
                    }
                    throw exception;
                }
            }
            return output.toByteArray();
        }
    }

    private static InputStream skipFully(InputStream input, long bytes) throws IOException {
        long remaining = bytes;
        while (remaining > 0) {
            long skipped = input.skip(remaining);
            if (skipped <= 0) {
                if (input.read() == -1) {
                    throw new IOException("Unexpected EOF while skipping FMF wrapper");
                }
                skipped = 1;
            }
            remaining -= skipped;
        }
        return input;
    }

    private record Anchor(int pair, int dateRel, int salaryRel) {
    }
}
