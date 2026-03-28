package com.fm26.save.analysis;

import com.github.luben.zstd.ZstdIOException;
import com.github.luben.zstd.ZstdInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class ContractEndCsvVerifier {

    private static final int FMF_ZSTD_OFFSET = 26;

    private ContractEndCsvVerifier() {
    }

    public static void main(String[] args) throws Exception {
        Path csv = args.length > 0 ? Path.of(args[0]) : Path.of("contract_end.csv");
        byte[] payload = loadPayload(Path.of("games/Feyenoord_after.fm"));
        List<Row> rows = readCsv(csv);

        int matches = 0;
        List<String> wrong = new ArrayList<>();
        List<String> missing = new ArrayList<>();

        for (Row row : rows) {
            IsolatedContractExtractor.Extraction extraction = IsolatedContractExtractor.extract(payload, row.id());
            IsolatedContractExtractor.ClusterCandidate best = extraction.best();
            if (best == null || best.contractEnd() == null || best.contractEnd().date() == null) {
                missing.add(row.id() + " " + row.name());
                continue;
            }
            LocalDate actual = best.contractEnd().date();
            if (actual.equals(row.contractEndDate())) {
                matches++;
            } else {
                wrong.add(row.id() + " " + row.name()
                        + " expected=" + row.contractEndDate()
                        + " actual=" + actual
                        + " anchor=" + best.anchor()
                        + " rel=" + best.contractEnd().rel());
            }
        }

        System.out.println("checked=" + rows.size());
        System.out.println("matches=" + matches);
        System.out.println("wrong=" + wrong.size());
        for (String line : wrong) {
            System.out.println("WRONG " + line);
        }
        System.out.println("missing=" + missing.size());
        for (String line : missing) {
            System.out.println("MISSING " + line);
        }
    }

    private static List<Row> readCsv(Path csv) throws IOException {
        List<Row> rows = new ArrayList<>();
        List<String> lines = Files.readAllLines(csv);
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split(",", 3);
            rows.add(new Row(
                    Integer.parseUnsignedInt(parts[0]),
                    parts[1],
                    LocalDate.parse(parts[2])));
        }
        return rows;
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

    private record Row(int id, String name, LocalDate contractEndDate) {
    }
}
