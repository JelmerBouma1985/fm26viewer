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

public final class LoanCsvVerifier {

    private static final int FMF_ZSTD_OFFSET = 26;

    private LoanCsvVerifier() {
    }

    public static void main(String[] args) throws Exception {
        Path csv = args.length > 0 ? Path.of(args[0]) : Path.of("loan.csv");
        byte[] payload = loadPayload(Path.of("games/Feyenoord_after.fm"));
        IsolatedContractExtractor.PreparedPayload prepared = IsolatedContractExtractor.prepare(payload);
        List<Row> rows = readCsv(csv);

        int parentMatches = 0;
        int loanMatches = 0;
        int salaryMatches = 0;
        List<String> parentWrong = new ArrayList<>();
        List<String> loanWrong = new ArrayList<>();
        List<String> salaryWrong = new ArrayList<>();
        List<String> missing = new ArrayList<>();

        for (Row row : rows) {
            IsolatedLoanExtractor.LoanExtraction extraction = IsolatedLoanExtractor.extract(prepared, row.id());
            if (extraction.anchor() < 0
                    || extraction.loanExpiry() == null
                    || extraction.parentExpiry() == null
                    || extraction.salary() == null) {
                missing.add(row.id() + " " + row.name());
                continue;
            }
            LocalDate actualLoan = extraction.loanExpiry().date();
            LocalDate actualParent = extraction.parentExpiry().date();
            int actualSalary = roundForDisplay(extraction.salary().value());

            if (actualParent.equals(row.parentContractEndDate())) {
                parentMatches++;
            } else {
                parentWrong.add(row.id() + " " + row.name()
                        + " expected=" + row.parentContractEndDate()
                        + " actual=" + actualParent);
            }

            if (actualLoan.equals(row.loanExpiryDate())) {
                loanMatches++;
            } else {
                loanWrong.add(row.id() + " " + row.name()
                        + " expected=" + row.loanExpiryDate()
                        + " actual=" + actualLoan);
            }

            if (actualSalary == row.salaryPerWeek()) {
                salaryMatches++;
            } else {
                salaryWrong.add(row.id() + " " + row.name()
                        + " expected=" + row.salaryPerWeek()
                        + " actual=" + actualSalary
                        + " raw=" + extraction.salary().value());
            }
        }

        System.out.println("checked=" + rows.size());
        System.out.println("parentMatches=" + parentMatches);
        System.out.println("loanMatches=" + loanMatches);
        System.out.println("salaryMatches=" + salaryMatches);
        System.out.println("parentWrong=" + parentWrong.size());
        for (String line : parentWrong) {
            System.out.println("PARENT_WRONG " + line);
        }
        System.out.println("loanWrong=" + loanWrong.size());
        for (String line : loanWrong) {
            System.out.println("LOAN_WRONG " + line);
        }
        System.out.println("salaryWrong=" + salaryWrong.size());
        for (String line : salaryWrong) {
            System.out.println("SALARY_WRONG " + line);
        }
        System.out.println("missing=" + missing.size());
        for (String line : missing) {
            System.out.println("MISSING " + line);
        }
    }

    private static int roundForDisplay(int raw) {
        int step;
        if (raw < 500) {
            step = 10;
        } else if (raw < 1_000) {
            step = 50;
        } else if (raw < 2_000) {
            step = 100;
        } else if (raw < 20_000) {
            step = 250;
        } else {
            step = 500;
        }
        return ((raw + (step / 2)) / step) * step;
    }

    private static List<Row> readCsv(Path csv) throws IOException {
        List<Row> rows = new ArrayList<>();
        List<String> lines = Files.readAllLines(csv);
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split(",", 5);
            rows.add(new Row(
                    Integer.parseUnsignedInt(parts[0]),
                    parts[1],
                    LocalDate.parse(parts[2]),
                    LocalDate.parse(parts[3]),
                    Integer.parseInt(parts[4])));
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

    private record Row(int id, String name, LocalDate loanExpiryDate, LocalDate parentContractEndDate, int salaryPerWeek) {
    }
}
