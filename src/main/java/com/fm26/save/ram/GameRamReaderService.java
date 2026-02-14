package com.fm26.save.ram;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Base64;
import java.io.OutputStream;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class GameRamReaderService {

    private static final String PROC_ROOT = "/proc";
    private static final int CHUNK_SIZE = 64 * 1024;
    // `/proc/<pid>/mem` reads can be expensive; keep dump sizes bounded.
    // 128 MiB is enough for our diff-based scans while remaining practical.
    private static final int MAX_DUMP_FILE_BYTES = 128 * 1024 * 1024;
    // Snapshots are kept in-memory for diffing; keep them small and bounded.
    private static final int MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024;
    private static final int MAX_SNAPSHOTS = 32;
    private static final int ANALYSIS_RADIUS = 512;
    private static final int POINTER_ANALYSIS_RADIUS = 128;
    private static final byte[] LVTP_CORE = new byte[]{
            0x01, 0x0a, 0x04, 0x00, 0x00, 0x00, 0x6c, 0x76, 0x74, 0x70 // 01 0a 04 00 00 00 'lvtp'
    };
    private static final byte[] LVTP_RUN_START_NEEDLE = new byte[]{
            0x01, 0x11, 0x00, // 01 11 <id=0>
            0x01, 0x0a, 0x04, 0x00, 0x00, 0x00, 0x6c, 0x76, 0x74, 0x70
    };
    private static final int LVTP_RECORD_LEN = 3 + LVTP_CORE.length + (3 * 7); // 01 11 <id> + core + (01 11 <v> <4-byte key>) x3
    private static final Set<String> WRAPPER_PROCESS_NAMES = Set.of(
            "sh", "bash", "steam", "steamwebhelper", "reaper", "steam-launch-wrapper"
    );
    private static final List<String> OUTFIELD_ATTR_ORDER_36 = List.of(
            // Technical (14)
            "corners", "crossing", "dribbling", "finishing", "firstTouch", "freeKickTaking",
            "heading", "longShots", "longThrows", "marking", "passing", "penaltyTaking",
            "tackling", "technique",
            // Mental (14)
            "aggression", "anticipation", "bravery", "composure", "concentration", "decisions",
            "determination", "flair", "leadership", "offTheBall", "positioning", "teamwork",
            "vision", "workRate",
            // Physical (8)
            "acceleration", "agility", "balance", "jumpingReach", "naturalFitness", "pace",
            "stamina", "strength"
    );

    private record Snapshot(int pid, long address, int size, byte[] bytes, String sha256) {
    }

    private record ActivePlayerNode(long address, int playerId, String firstName, String lastName) {
    }

    private final ConcurrentMap<String, Snapshot> snapshots = new ConcurrentHashMap<>();
    private final Deque<String> snapshotFifo = new ArrayDeque<>();

    public PatternScanResult scanForPatternByPid(int pid,
                                                 List<Integer> pattern,
                                                 int baseIndex,
                                                 int maxHits,
                                                 boolean anonymousWritableOnly,
                                                 long maxBytesPerRegion,
                                                 boolean unordered,
                                                 int maxRegions,
                                                 String regionStart,
                                                 String regionEnd,
                                                 String encodings) {
        if (pattern == null || pattern.isEmpty()) {
            throw new IllegalArgumentException("pattern is required");
        }
        if (baseIndex < 0 || baseIndex > 35) {
            throw new IllegalArgumentException("baseIndex must be between 0 and 35");
        }
        if (maxHits <= 0) {
            throw new IllegalArgumentException("maxHits must be > 0");
        }

        RunningProcess process = describeProcess(pid);
        List<MemoryRegion> regions = listMemoryRegions(process.pid());

        List<PatternScanHit> hits = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        if (maxRegions <= 0) {
            throw new IllegalArgumentException("maxRegions must be > 0");
        }

        Long restrictStart = null;
        Long restrictEnd = null;
        if (regionStart != null && !regionStart.isBlank()) {
            restrictStart = parseAddress(regionStart);
        }
        if (regionEnd != null && !regionEnd.isBlank()) {
            restrictEnd = parseAddress(regionEnd);
        }
        if (restrictStart != null && restrictEnd != null && restrictEnd < restrictStart) {
            throw new IllegalArgumentException("regionEnd must be >= regionStart");
        }

        List<MemoryRegion> candidates = new ArrayList<>();
        for (MemoryRegion r : regions) {
            if (!r.readable()) continue;
            if (anonymousWritableOnly && !r.anonymousWritable()) continue;
            if (restrictStart != null || restrictEnd != null) {
                long rs = restrictStart == null ? Long.MIN_VALUE : restrictStart;
                long re = restrictEnd == null ? Long.MAX_VALUE : restrictEnd;
                // overlap test
                if (r.endAddress() <= rs || r.startAddress() >= re) {
                    continue;
                }
            }
            candidates.add(r);
        }
        candidates.sort((a, b) -> Long.compare((b.endAddress() - b.startAddress()), (a.endAddress() - a.startAddress())));
        if (candidates.size() > maxRegions) {
            candidates = candidates.subList(0, maxRegions);
        }

        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            for (MemoryRegion region : candidates) {
                if (hits.size() >= maxHits) break;
                scanRegionForPattern(memFile, region, pattern, baseIndex, maxHits, maxBytesPerRegion, unordered, encodings, hits, warnings);
            }
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
        }

        return new PatternScanResult(process.pid(), process.name(), process.command(), pattern, baseIndex, hits, warnings);
    }

    public BagScanResult scanForBagByPid(int pid,
                                         List<Integer> bag,
                                         int windowBytes,
                                         int stepBytes,
                                         int maxHits,
                                         boolean anonymousWritableOnly,
                                         boolean noExecOnly,
                                         int maxRegions,
                                         long maxBytesPerRegion,
                                         String regionStart,
                                         String regionEnd) {
        if (bag == null || bag.isEmpty()) {
            throw new IllegalArgumentException("bag is required");
        }
        if (windowBytes <= 0) {
            throw new IllegalArgumentException("windowBytes must be > 0");
        }
        if (stepBytes <= 0) {
            throw new IllegalArgumentException("stepBytes must be > 0");
        }
        if (maxHits <= 0) {
            throw new IllegalArgumentException("maxHits must be > 0");
        }
        if (maxRegions <= 0) {
            throw new IllegalArgumentException("maxRegions must be > 0");
        }

        RunningProcess process = describeProcess(pid);
        List<MemoryRegion> regions = listMemoryRegions(process.pid());
        List<String> warnings = new ArrayList<>();

        Long restrictStart = null;
        Long restrictEnd = null;
        if (regionStart != null && !regionStart.isBlank()) {
            restrictStart = parseAddress(regionStart);
        }
        if (regionEnd != null && !regionEnd.isBlank()) {
            restrictEnd = parseAddress(regionEnd);
        }
        if (restrictStart != null && restrictEnd != null && restrictEnd < restrictStart) {
            throw new IllegalArgumentException("regionEnd must be >= regionStart");
        }

        List<MemoryRegion> candidates = new ArrayList<>();
        for (MemoryRegion r : regions) {
            if (!r.readable()) continue;
            if (anonymousWritableOnly && !r.anonymousWritable()) continue;
            if (noExecOnly && r.executable()) continue;
            if (restrictStart != null || restrictEnd != null) {
                long rs = restrictStart == null ? Long.MIN_VALUE : restrictStart;
                long re = restrictEnd == null ? Long.MAX_VALUE : restrictEnd;
                if (r.endAddress() <= rs || r.startAddress() >= re) continue;
            }
            candidates.add(r);
        }
        candidates.sort((a, b) -> Long.compare((b.endAddress() - b.startAddress()), (a.endAddress() - a.startAddress())));
        if (candidates.size() > maxRegions) {
            candidates = candidates.subList(0, maxRegions);
        }

        List<BagScanHit> hits = new ArrayList<>();
        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            for (MemoryRegion region : candidates) {
                if (hits.size() >= maxHits) break;
                scanRegionForBag(memFile, region, bag, windowBytes, stepBytes, maxHits, maxBytesPerRegion, hits, warnings);
            }
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
        }

        return new BagScanResult(process.pid(), process.name(), process.command(), bag, windowBytes, stepBytes, hits, warnings);
    }

    private void scanRegionForBag(RandomAccessFile memFile,
                                  MemoryRegion region,
                                  List<Integer> bag,
                                  int windowBytes,
                                  int stepBytes,
                                  int maxHits,
                                  long maxBytesPerRegion,
                                  List<BagScanHit> hits,
                                  List<String> warnings) {
        // Try u32 first (Unity structs commonly align to 4 bytes), then u16, then byte.
        scanRegionForBagAligned(memFile, region, bag, windowBytes, stepBytes, maxHits, maxBytesPerRegion, hits, warnings, 4, "u32_le");
        if (hits.size() >= maxHits) return;
        scanRegionForBagAligned(memFile, region, bag, windowBytes, stepBytes, maxHits, maxBytesPerRegion, hits, warnings, 2, "u16_le");
        if (hits.size() >= maxHits) return;
        scanRegionForBagAligned(memFile, region, bag, windowBytes, stepBytes, maxHits, maxBytesPerRegion, hits, warnings, 1, "byte");
    }

    private void scanRegionForBagAligned(RandomAccessFile memFile,
                                         MemoryRegion region,
                                         List<Integer> bag,
                                         int windowBytes,
                                         int stepBytes,
                                         int maxHits,
                                         long maxBytesPerRegion,
                                         List<BagScanHit> hits,
                                         List<String> warnings,
                                         int elementBytes,
                                         String encoding) {
        long regionSize = region.endAddress() - region.startAddress();
        long maxScan = Math.min(regionSize, maxBytesPerRegion);
        int step = Math.max(elementBytes, stepBytes);
        int effectiveWindow = Math.max(elementBytes, windowBytes - (windowBytes % elementBytes));
        if (effectiveWindow <= 0) effectiveWindow = elementBytes;

        byte[] buf = new byte[effectiveWindow];
        for (long off = 0; off + effectiveWindow <= maxScan && hits.size() < maxHits; off += step) {
            long address = region.startAddress() + off;
            try {
                memFile.seek(address);
                int read = memFile.read(buf);
                if (read < effectiveWindow) {
                    break;
                }
            } catch (IOException e) {
                warnings.add("Bag scan read failed at 0x" + Long.toHexString(address) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            if (!windowContainsAll(buf, bag, elementBytes)) {
                continue;
            }
            hits.add(new BagScanHit(
                    address,
                    String.format("0x%016X", address),
                    region.shortLabel(),
                    encoding,
                    elementBytes,
                    effectiveWindow
            ));
        }
    }

    private boolean windowContainsAll(byte[] window, List<Integer> bag, int elementBytes) {
        // Treat the bag as a multiset (duplicates supported).
        Map<Integer, Integer> need = new LinkedHashMap<>();
        for (int v : bag) {
            need.put(v, need.getOrDefault(v, 0) + 1);
        }
        Map<Integer, Integer> have = new HashMap<>();
        int remaining = need.size();

        int limit = window.length - elementBytes;
        for (int off = 0; off <= limit; off += elementBytes) {
            int v;
            if (elementBytes == 1) {
                v = window[off] & 0xFF;
            } else if (elementBytes == 2) {
                v = (window[off] & 0xFF) | ((window[off + 1] & 0xFF) << 8);
            } else {
                v = (window[off] & 0xFF)
                        | ((window[off + 1] & 0xFF) << 8)
                        | ((window[off + 2] & 0xFF) << 16)
                        | ((window[off + 3] & 0xFF) << 24);
            }
            Integer needed = need.get(v);
            if (needed == null) continue;

            int newCount = have.getOrDefault(v, 0) + 1;
            if (newCount > needed) continue;
            have.put(v, newCount);
            if (newCount == needed) {
                remaining--;
                if (remaining == 0) return true;
            }
        }
        return false;
    }

    public IntScanResult scanForInt32ByPid(int pid,
                                          int value,
                                          int maxHits,
                                          long maxBytesPerRegion,
                                          boolean anonymousWritableOnly,
                                          boolean noExecOnly,
                                          boolean scanPointers,
                                          long maxPointerScanBytesPerRegion,
                                          int maxPointerReferencesPerHit,
                                          String regionStart,
                                          String regionEnd) {
        if (maxHits <= 0) throw new IllegalArgumentException("maxHits must be > 0");
        if (maxBytesPerRegion <= 0) throw new IllegalArgumentException("maxBytesPerRegion must be > 0");

        RunningProcess process = describeProcess(pid);
        List<MemoryRegion> regions = listMemoryRegions(process.pid());
        List<String> warnings = new ArrayList<>();

        Long restrictStart = null;
        Long restrictEnd = null;
        if (regionStart != null && !regionStart.isBlank()) {
            restrictStart = parseAddress(regionStart);
        }
        if (regionEnd != null && !regionEnd.isBlank()) {
            restrictEnd = parseAddress(regionEnd);
        }
        if (restrictStart != null && restrictEnd != null && restrictEnd < restrictStart) {
            throw new IllegalArgumentException("regionEnd must be >= regionStart");
        }

        List<MemoryRegion> candidates = new ArrayList<>();
        for (MemoryRegion r : regions) {
            if (!r.readable()) continue;
            if (anonymousWritableOnly && !r.anonymousWritable()) continue;
            if (noExecOnly && r.executable()) continue;
            if (restrictStart != null || restrictEnd != null) {
                long rs = restrictStart == null ? Long.MIN_VALUE : restrictStart;
                long re = restrictEnd == null ? Long.MAX_VALUE : restrictEnd;
                if (r.endAddress() <= rs || r.startAddress() >= re) continue;
            }
            candidates.add(r);
        }
        candidates.sort((a, b) -> Long.compare(b.size(), a.size()));

        List<IntScanHit> hits = new ArrayList<>();
        int scannedRegions = 0;
        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            for (MemoryRegion region : candidates) {
                if (hits.size() >= maxHits) break;
                scannedRegions++;
                scanRegionForInt32(memFile, region, value, maxHits, maxBytesPerRegion, hits, warnings);
            }

            if (scanPointers && !hits.isEmpty()) {
                hits = enrichIntHitsWithPointers(
                        memFile,
                        regions,
                        hits,
                        anonymousWritableOnly,
                        noExecOnly,
                        maxPointerScanBytesPerRegion,
                        maxPointerReferencesPerHit,
                        warnings
                );
            }
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
        }

        return new IntScanResult(process.pid(), process.name(), process.command(), value, scannedRegions, hits, warnings);
    }

    public AnalyzeIntResult analyzeInt32ByPid(int pid,
                                             int value,
                                             int maxHits,
                                             long maxBytesPerRegion,
                                             boolean anonymousWritableOnly,
                                             boolean noExecOnly,
                                             int windowBytes,
                                             int maxAnalyzedHits,
                                             String regionStart,
                                             String regionEnd) {
        if (windowBytes <= 0) throw new IllegalArgumentException("windowBytes must be > 0");
        if (maxAnalyzedHits <= 0) throw new IllegalArgumentException("maxAnalyzedHits must be > 0");

        IntScanResult raw = scanForInt32ByPid(
                pid,
                value,
                maxHits,
                maxBytesPerRegion,
                anonymousWritableOnly,
                noExecOnly,
                false,
                0,
                0,
                regionStart,
                regionEnd
        );

        List<String> warnings = new ArrayList<>(raw.warnings());
        List<AnalyzeIntHit> analyzedHits = new ArrayList<>();
        int analyzed = 0;

        Path memPath = Path.of(PROC_ROOT, String.valueOf(raw.pid()), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            for (IntScanHit h : raw.hits()) {
                if (analyzed >= maxAnalyzedHits) break;
                analyzed++;
                AttributeBlockGuess guess = guessAttributeBlockNear(memFile, h.address(), windowBytes, warnings);
                analyzedHits.add(new AnalyzeIntHit(h.address(), h.addressHex(), h.region(), h.value(), guess));
            }
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
        }

        return new AnalyzeIntResult(raw.pid(), raw.processName(), raw.command(), raw.value(), raw.scannedRegions(), analyzedHits, warnings);
    }

    private AttributeBlockGuess guessAttributeBlockNear(RandomAccessFile memFile,
                                                       long hitAddress,
                                                       int windowBytes,
                                                       List<String> warnings) {
        // Read a window centered at hitAddress.
        int half = windowBytes / 2;
        long start = Math.max(0, hitAddress - half);
        byte[] buf = new byte[windowBytes];
        int bytesRead;
        try {
            memFile.seek(start);
            bytesRead = memFile.read(buf);
            if (bytesRead <= 0) return null;
            if (bytesRead < buf.length) {
                byte[] resized = new byte[bytesRead];
                System.arraycopy(buf, 0, resized, 0, bytesRead);
                buf = resized;
            }
        } catch (IOException e) {
            warnings.add("Analyze-int read failed at 0x" + Long.toHexString(start) + ": " + e.getMessage());
            return null;
        }

        // Look for a 36-value block where most values are in [1..20].
        // Real game structs often store values with padding/stride, so we try multiple strides per encoding.
        AttributeBlockGuess best = null;

        // byte values, common strides
        for (int stride : List.of(1, 2, 4, 8, 12, 16)) {
            best = pickBetter(best, bestAttributeBlockGeneric(buf, start, hitAddress, "byte", 1, stride));
        }
        // u16 little endian, common strides
        for (int stride : List.of(2, 4, 6, 8, 10, 12, 14, 16)) {
            best = pickBetter(best, bestAttributeBlockGeneric(buf, start, hitAddress, "u16", 2, stride));
        }
        // u32 little endian, common strides
        for (int stride : List.of(4, 8, 12, 16, 20, 24, 28, 32)) {
            best = pickBetter(best, bestAttributeBlockGeneric(buf, start, hitAddress, "u32", 4, stride));
        }

        return best;
    }

    public PointerFollowResult followPointers(int pid,
                                             String rootAddressHex,
                                             int bytes,
                                             int maxCandidates,
                                             boolean anonymousWritableOnly,
                                             boolean noExecOnly,
                                             boolean analyzeTargets,
                                             int targetWindowBytes) {
        if (bytes <= 0) throw new IllegalArgumentException("bytes must be > 0");
        if (bytes > 1024 * 1024) throw new IllegalArgumentException("bytes must be <= 1048576");
        if (maxCandidates <= 0) throw new IllegalArgumentException("maxCandidates must be > 0");
        if (targetWindowBytes <= 0) throw new IllegalArgumentException("targetWindowBytes must be > 0");
        if (targetWindowBytes > 4 * 1024 * 1024) throw new IllegalArgumentException("targetWindowBytes must be <= 4194304");

        long rootAddress = parseAddress(rootAddressHex);
        RunningProcess process = describeProcess(pid);
        List<MemoryRegion> regions = listMemoryRegions(process.pid());
        List<String> warnings = new ArrayList<>();

        // Read the root window.
        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");
        byte[] buf = new byte[bytes];
        int read;
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            memFile.seek(rootAddress);
            read = memFile.read(buf);
            if (read <= 0) {
                read = 0;
                buf = new byte[0];
            } else if (read < buf.length) {
                buf = Arrays.copyOf(buf, read);
            }

            // Interpret 8-byte slots as candidate pointers.
            // We don't assume alignment; scan every 8 bytes, starting at 0.
            int scannedSlots = 0;
            Map<Long, Long> firstPointerAddrByTarget = new LinkedHashMap<>();
            for (int off = 0; off + 7 < buf.length; off += 8) {
                scannedSlots++;
                long target = readLongLittleEndian(buf, off);
                if (target == 0) continue;
                if (!firstPointerAddrByTarget.containsKey(target)) {
                    firstPointerAddrByTarget.put(target, rootAddress + off);
                    if (firstPointerAddrByTarget.size() >= (long) maxCandidates * 4) break; // keep bounded
                }
            }

            // Filter to targets that are inside known memory regions.
            List<PointerFollowCandidate> out = new ArrayList<>();
            Set<Long> seen = new HashSet<>();
            for (Map.Entry<Long, Long> e : firstPointerAddrByTarget.entrySet()) {
                if (out.size() >= maxCandidates) break;
                long target = e.getKey();
                if (!seen.add(target)) continue;
                MemoryRegion r = findRegionContaining(regions, target);
                if (r == null) continue;
                if (!r.readable()) continue;
                if (anonymousWritableOnly && !r.anonymousWritable()) continue;
                if (noExecOnly && r.executable()) continue;

                AttributeBlockGuess guess = null;
                if (analyzeTargets) {
                    guess = guessAttributeBlockNear(memFile, target, targetWindowBytes, warnings);
                }
                long ptrAddr = e.getValue();
                out.add(new PointerFollowCandidate(
                        ptrAddr,
                        String.format("0x%016X", ptrAddr),
                        target,
                        String.format("0x%016X", target),
                        r.shortLabel(),
                        guess
                ));
            }

            return new PointerFollowResult(
                    process.pid(),
                    process.name(),
                    process.command(),
                    rootAddress,
                    String.format("0x%016X", rootAddress),
                    buf.length,
                    scannedSlots,
                    List.copyOf(out),
                    warnings
            );
        } catch (IOException ex) {
            warnings.add("Could not open process memory file " + memPath + ": " + ex.getMessage());
            return new PointerFollowResult(
                    process.pid(),
                    process.name(),
                    process.command(),
                    rootAddress,
                    String.format("0x%016X", rootAddress),
                    0,
                    0,
                    List.of(),
                    warnings
            );
        }
    }

    private MemoryRegion findRegionContaining(List<MemoryRegion> regions, long address) {
        // regions are not necessarily sorted; linear scan is ok for one-off queries.
        for (MemoryRegion r : regions) {
            if (address >= r.startAddress() && address < r.endAddress()) return r;
        }
        return null;
    }

    public PlayerAttributesByIdResult playerAttributesById(int pid,
                                                          int playerId,
                                                          int maxIdHits,
                                                          boolean anonymousWritableOnly,
                                                          boolean noExecOnly,
                                                          int followBytes,
                                                          int followMaxCandidates,
                                                          int targetWindowBytes) {
        if (maxIdHits <= 0) throw new IllegalArgumentException("maxIdHits must be > 0");
        if (followBytes <= 0) throw new IllegalArgumentException("followBytes must be > 0");
        if (followMaxCandidates <= 0) throw new IllegalArgumentException("followMaxCandidates must be > 0");

        // Find occurrences of the player id.
        IntScanResult scan = scanForInt32ByPid(
                pid,
                playerId,
                maxIdHits,
                33_554_432L,
                anonymousWritableOnly,
                noExecOnly,
                false,
                0,
                0,
                null,
                null
        );
        List<String> warnings = new ArrayList<>(scan.warnings());
        if (scan.hits().isEmpty()) {
            return new PlayerAttributesByIdResult(
                    scan.pid(),
                    scan.processName(),
                    scan.command(),
                    playerId,
                    scan.scannedRegions(),
                    0,
                    null,
                    null,
                    null,
                    null,
                    null,
                    0,
                    null,
                    null,
                    List.of(),
                    Map.of(),
                    warnings
            );
        }

        // For each id-hit, try to follow pointers from nearby bytes and pick the best attribute-like target.
        record Best(
                IntScanHit idHit,
                PointerFollowCandidate cand,
                long blockStart,
                AttributeBlockGuess guess
        ) {}
        Best best = null;

        for (IntScanHit idHit : scan.hits()) {
            // Heuristic: the id is often inside a small struct; start a little before the hit.
            long root = Math.max(0, idHit.address() - 0x80);
            PointerFollowResult follow = followPointers(
                    scan.pid(),
                    String.format("0x%016X", root),
                    followBytes,
                    followMaxCandidates,
                    anonymousWritableOnly,
                    noExecOnly,
                    true,
                    targetWindowBytes
            );
            warnings.addAll(follow.warnings());

            for (PointerFollowCandidate c : follow.candidates()) {
                AttributeBlockGuess g = c.bestAttributeBlock();
                if (g == null) continue;
                // Only consider "good" guesses: mostly in 1..20 with decent variety.
                if (g.inRangeCount() < 32) continue;
                if (g.uniqueCount() < 8) continue;
                long blockStart = c.targetAddress() + (long) g.offsetFromHit();

                if (best == null || g.score() > best.guess.score()) {
                    best = new Best(idHit, c, blockStart, g);
                }
            }
        }

        if (best == null) {
            return new PlayerAttributesByIdResult(
                    scan.pid(),
                    scan.processName(),
                    scan.command(),
                    playerId,
                    scan.scannedRegions(),
                    scan.hits().size(),
                    scan.hits().getFirst().addressHex(),
                    scan.hits().getFirst().region(),
                    null,
                    null,
                    null,
                    0,
                    null,
                    null,
                    List.of(),
                    Map.of(),
                    warnings
            );
        }

        List<Integer> values36 = best.guess.values();
        Map<String, Integer> attrs = toOutfieldAttributeMap(values36);

        return new PlayerAttributesByIdResult(
                scan.pid(),
                scan.processName(),
                scan.command(),
                playerId,
                scan.scannedRegions(),
                scan.hits().size(),
                best.idHit.addressHex(),
                best.idHit.region(),
                best.cand.pointerAddressHex(),
                best.cand.targetAddressHex(),
                best.cand.targetRegion(),
                best.guess.offsetFromHit(),
                String.format("0x%016X", best.blockStart),
                best.guess,
                values36,
                attrs,
                warnings
        );
    }

    private record BestGuess(
            PointerFollowCandidate cand,
            long blockStart,
            AttributeBlockGuess guess
    ) {
    }

    private BestGuess bestGuessFromRoot(int pid,
                                        long rootAddress,
                                        boolean anonymousWritableOnly,
                                        boolean noExecOnly,
                                        int followBytes,
                                        int followMaxCandidates,
                                        int targetWindowBytes,
                                        List<String> warnings) {
        PointerFollowResult follow = followPointers(
                pid,
                String.format("0x%016X", rootAddress),
                followBytes,
                followMaxCandidates,
                anonymousWritableOnly,
                noExecOnly,
                true,
                targetWindowBytes
        );
        warnings.addAll(follow.warnings());
        BestGuess best = null;
        for (PointerFollowCandidate c : follow.candidates()) {
            AttributeBlockGuess g = c.bestAttributeBlock();
            if (g == null) continue;
            if (g.inRangeCount() < 32) continue;
            if (g.uniqueCount() < 8) continue;
            long blockStart = c.targetAddress() + (long) g.offsetFromHit();
            if (best == null || g.score() > best.guess.score()) {
                best = new BestGuess(c, blockStart, g);
            }
        }
        return best;
    }

    public EnumeratePlayersResult enumeratePlayersInRegion(int pid,
                                                          String regionStartHex,
                                                          String regionEndHex,
                                                          int maxPlayers,
                                                          boolean anonymousWritableOnly,
                                                          boolean noExecOnly,
                                                          boolean validateWithAttributes,
                                                          int maxValidate,
                                                          int followBytes,
                                                          int followMaxCandidates,
                                                          int targetWindowBytes) {
        if (maxPlayers <= 0) throw new IllegalArgumentException("maxPlayers must be > 0");
        if (maxValidate <= 0) throw new IllegalArgumentException("maxValidate must be > 0");
        long regionStart = parseAddress(regionStartHex);
        long regionEnd = parseAddress(regionEndHex);
        if (regionEnd <= regionStart) throw new IllegalArgumentException("regionEnd must be > regionStart");

        RunningProcess process = describeProcess(pid);
        List<MemoryRegion> regions = listMemoryRegions(process.pid());
        MemoryRegion region = null;
        for (MemoryRegion r : regions) {
            if (r.startAddress() == regionStart && r.endAddress() == regionEnd) {
                region = r;
                break;
            }
        }
        String regionLabel = String.format("0x%016X-0x%016X", regionStart, regionEnd)
                + (region != null ? (" " + region.permissions() + " " + region.path()) : "");

        List<String> warnings = new ArrayList<>();
        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");

        // Scan the region for structs that look like:
        //   +0x20: int32 playerId
        //   +0x28: ptr to first name (usually length-prefixed ASCII)
        //   +0x30: ptr to last name (usually length-prefixed ASCII)
        //
        // This matches what we observed around Haaland (29179241) at 0x7ECD5100.
        LinkedHashSet<Integer> candidateIds = new LinkedHashSet<>();
        Map<Integer, EnumeratedPlayer> candidatePlayers = new LinkedHashMap<>();

        int scannedSlots = 0;
        int candidateStructs = 0;
        long maxScan = regionEnd - regionStart;
        if (maxScan > 64L * 1024 * 1024) {
            warnings.add("Region too large; capped scan to 64MiB");
            maxScan = 64L * 1024 * 1024;
        }

        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            byte[] buf = new byte[(int) Math.min(maxScan, 16L * 1024 * 1024)]; // read at most 16MiB at once
            long offset = 0;
            while (offset < maxScan && candidateIds.size() < (long) maxPlayers * 5) {
                int toRead = (int) Math.min(buf.length, maxScan - offset);
                memFile.seek(regionStart + offset);
                int read = memFile.read(buf, 0, toRead);
                if (read <= 0) break;
                byte[] chunk = read == toRead ? buf : Arrays.copyOf(buf, read);

                for (int off = 0; off + 0x38 <= chunk.length; off += 8) {
                    scannedSlots++;
                    long structAddr = regionStart + offset + off;
                    int id = readInt32LittleEndian(chunk, off + 0x20);
                    if (id < 1_000_000 || id > 150_000_000) continue;

                    long pFirst = readLongLittleEndian(chunk, off + 0x28);
                    long pLast = readLongLittleEndian(chunk, off + 0x30);
                    if (!isLikelyPointer(regions, pFirst, anonymousWritableOnly, noExecOnly)) continue;
                    if (!isLikelyPointer(regions, pLast, anonymousWritableOnly, noExecOnly)) continue;

                    String first = readNameString(memFile, pFirst, 32, warnings);
                    if (first == null) continue;
                    String last = readNameString(memFile, pLast, 32, warnings);
                    if (last == null) continue;
                    if (!isPlausibleFirstName(first) || !isPlausibleLastName(last, first)) continue;

                    candidateStructs++;
                    candidateIds.add(id);
                    if (!candidatePlayers.containsKey(id)) {
                        MemoryRegion sr = findRegionContaining(regions, structAddr);
                        candidatePlayers.put(id, new EnumeratedPlayer(
                                id,
                                first,
                                last,
                                structAddr,
                                String.format("0x%016X", structAddr),
                                sr == null ? regionLabel : sr.shortLabel(),
                                null,
                                Map.of()
                        ));
                    }
                    if (candidatePlayers.size() >= maxPlayers) break;
                }

                offset += read;
                if (candidatePlayers.size() >= maxPlayers) break;
            }

            List<EnumeratedPlayer> out = new ArrayList<>(candidatePlayers.values());
            int validated = 0;
            if (validateWithAttributes) {
                List<EnumeratedPlayer> validatedOut = new ArrayList<>();
                for (EnumeratedPlayer p : out) {
                    if (validatedOut.size() >= Math.min(maxPlayers, maxValidate)) break;
                    // Validate quickly by following pointers from the struct address we already discovered.
                    BestGuess g = bestGuessFromRoot(
                            process.pid(),
                            Math.max(0, p.structAddress() - 0x80),
                            anonymousWritableOnly,
                            noExecOnly,
                            followBytes,
                            followMaxCandidates,
                            targetWindowBytes,
                            warnings
                    );
                    if (g == null) continue;
                    Map<String, Integer> attrs = toOutfieldAttributeMap(g.guess.values());
                    if (attrs.isEmpty()) continue;
                    Integer score = g.guess.score();
                    validated++;
                    validatedOut.add(new EnumeratedPlayer(
                            p.playerId(),
                            p.firstName(),
                            p.lastName(),
                            p.structAddress(),
                            p.structAddressHex(),
                            p.region(),
                            score,
                            attrs
                    ));
                }
                out = validatedOut;
            }

            return new EnumeratePlayersResult(
                    process.pid(),
                    process.name(),
                    process.command(),
                    regionLabel,
                    (int) maxScan,
                    scannedSlots,
                    candidateStructs,
                    candidateIds.size(),
                    validated,
                    List.copyOf(out),
                    warnings
            );
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
            return new EnumeratePlayersResult(
                    process.pid(),
                    process.name(),
                    process.command(),
                    regionLabel,
                    0,
                    0,
                    0,
                    0,
                    0,
                    List.of(),
                    warnings
            );
        }
    }

    private boolean isLikelyPointer(List<MemoryRegion> regions, long address, boolean anonymousWritableOnly, boolean noExecOnly) {
        MemoryRegion r = findRegionContaining(regions, address);
        if (r == null) return false;
        if (!r.readable()) return false;
        if (anonymousWritableOnly && !r.anonymousWritable()) return false;
        if (noExecOnly && r.executable()) return false;
        return true;
    }

    private int readInt32LittleEndian(byte[] buf, int off) {
        return (buf[off] & 0xFF)
                | ((buf[off + 1] & 0xFF) << 8)
                | ((buf[off + 2] & 0xFF) << 16)
                | ((buf[off + 3] & 0xFF) << 24);
    }

    private String readNameString(RandomAccessFile memFile, long address, int maxLen, List<String> warnings) {
        try {
            byte[] tmp = new byte[Math.max(maxLen, 8)];
            memFile.seek(address);
            int n = memFile.read(tmp);
            if (n <= 0) return null;

            // Try length-prefixed format first: <u32 len><ascii bytes...>
            if (n >= 6) {
                int len = readInt32LittleEndian(tmp, 0);
                if (len >= 2 && len <= maxLen && 4 + len <= n) {
                    if (isNiceNameBytes(tmp, 4, len)) {
                        return new String(tmp, 4, len, StandardCharsets.US_ASCII);
                    }
                }
            }

            // Fallback: NUL-terminated ASCII.
            int end = 0;
            while (end < n && tmp[end] != 0) end++;
            if (end < 2 || end > maxLen) return null;
            if (!isNiceNameBytes(tmp, 0, end)) return null;
            return new String(tmp, 0, end, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            warnings.add("Failed to read string at 0x" + Long.toHexString(address) + ": " + e.getMessage());
            return null;
        }
    }

    private boolean isNiceNameBytes(byte[] buf, int start, int len) {
        for (int i = 0; i < len; i++) {
            int c = buf[start + i] & 0xFF;
            boolean ok = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || c == ' ' || c == '-' || c == '\'' || c == '.';
            if (!ok) return false;
        }
        return true;
    }

    private boolean isPlausibleFirstName(String first) {
        if (first == null) return false;
        String s = first.trim();
        if (s.length() < 2 || s.length() > 16) return false;
        if (s.indexOf(' ') >= 0) return false;
        char c0 = s.charAt(0);
        if (!(c0 >= 'A' && c0 <= 'Z')) return false;
        // Avoid obvious non-names that show up in memory.
        if (s.equalsIgnoreCase("Server") || s.equalsIgnoreCase("Connection")) return false;
        return true;
    }

    private boolean isPlausibleLastName(String last, String first) {
        if (last == null) return false;
        String s = last.trim();
        if (s.length() < 2 || s.length() > 28) return false;
        if (first != null && s.equalsIgnoreCase(first.trim())) return false;
        // Require at least one lowercase letter to filter things like "FA" or "CUP" blocks.
        boolean hasLower = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'a' && c <= 'z') {
                hasLower = true;
                break;
            }
        }
        if (!hasLower) return false;
        String low = s.toLowerCase(java.util.Locale.ROOT);
        if (low.contains("league") || low.contains("cup") || low.contains("trophy")) return false;
        return true;
    }

    private static AttributeBlockGuess pickBetter(AttributeBlockGuess a, AttributeBlockGuess b) {
        if (a == null) return b;
        if (b == null) return a;
        return b.score() > a.score() ? b : a;
    }

    private static AttributeBlockGuess bestAttributeBlockGeneric(byte[] buf,
                                                                 long windowStartAddr,
                                                                 long hitAddress,
                                                                 String encoding,
                                                                 int valueBytes,
                                                                 int strideBytes) {
        int valuesN = 36;
        int span = Math.max(0, (valuesN - 1) * strideBytes) + valueBytes;
        if (buf.length < span) return null;

        AttributeBlockGuess best = null;
        int maxOffset = buf.length - span;
        for (int off = 0; off <= maxOffset; off++) {
            // Heuristic: require the first few values to be plausible to save work.
            int v0 = readValueLE(buf, off, valueBytes);
            int v1 = readValueLE(buf, off + strideBytes, valueBytes);
            if (v0 < 1 || v0 > 20 || v1 < 1 || v1 > 20) continue;

            int inRange = 0;
            int min = Integer.MAX_VALUE;
            int max = Integer.MIN_VALUE;
            boolean[] seen = new boolean[32]; // attributes are 1..20, small
            int unique = 0;
            int[] values = new int[valuesN];

            for (int i = 0; i < valuesN; i++) {
                int v = readValueLE(buf, off + i * strideBytes, valueBytes);
                values[i] = v;
                if (v >= 1 && v <= 20) inRange++;
                if (v < min) min = v;
                if (v > max) max = v;
                if (v >= 1 && v < seen.length) {
                    if (!seen[v]) {
                        seen[v] = true;
                        unique++;
                    }
                }
            }

            // Score: prefer blocks mostly in [1..20] and with decent variety.
            if (inRange < 30) continue;
            int score = inRange * 10 + unique * 3 - Math.abs((int) ((windowStartAddr + off) - hitAddress)) / 64;
            if (best == null || score > best.score()) {
                java.util.List<Integer> vals = new java.util.ArrayList<>(valuesN);
                for (int v : values) vals.add(v);
                best = new AttributeBlockGuess(
                        encoding + "_stride" + strideBytes,
                        (int) ((windowStartAddr + off) - hitAddress),
                        score,
                        inRange,
                        unique,
                        min,
                        max,
                        java.util.List.copyOf(vals)
                );
            }
        }
        return best;
    }

    private static int readValueLE(byte[] buf, int off, int valueBytes) {
        if (valueBytes == 1) return buf[off] & 0xFF;
        if (valueBytes == 2) {
            int b0 = buf[off] & 0xFF;
            int b1 = buf[off + 1] & 0xFF;
            return (b1 << 8) | b0;
        }
        // valueBytes == 4
        int b0 = buf[off] & 0xFF;
        int b1 = buf[off + 1] & 0xFF;
        int b2 = buf[off + 2] & 0xFF;
        int b3 = buf[off + 3] & 0xFF;
        return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    }

    private void scanRegionForInt32(RandomAccessFile memFile,
                                    MemoryRegion region,
                                    int value,
                                    int maxHits,
                                    long maxBytesPerRegion,
                                    List<IntScanHit> hits,
                                    List<String> warnings) {
        long maxScan = Math.min(region.size(), maxBytesPerRegion);
        long offsetInRegion = 0;
        byte[] tail = new byte[0];
        byte[] needle = new byte[4];
        needle[0] = (byte) (value & 0xFF);
        needle[1] = (byte) ((value >>> 8) & 0xFF);
        needle[2] = (byte) ((value >>> 16) & 0xFF);
        needle[3] = (byte) ((value >>> 24) & 0xFF);

        while (offsetInRegion < maxScan && hits.size() < maxHits) {
            int toRead = (int) Math.min(CHUNK_SIZE, maxScan - offsetInRegion);
            byte[] chunk = new byte[toRead];
            long absoluteStart = region.startAddress() + offsetInRegion;
            try {
                memFile.seek(absoluteStart);
                int bytesRead = memFile.read(chunk);
                if (bytesRead <= 0) break;
                if (bytesRead < toRead) {
                    byte[] resized = new byte[bytesRead];
                    System.arraycopy(chunk, 0, resized, 0, bytesRead);
                    chunk = resized;
                }
            } catch (IOException e) {
                warnings.add("Int32 scan read failed at 0x" + Long.toHexString(absoluteStart) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            byte[] merged = concat(tail, chunk);
            long mergedStartAddress = absoluteStart - tail.length;
            for (int i = 0; i + 3 < merged.length && hits.size() < maxHits; i++) {
                if (merged[i] != needle[0] || merged[i + 1] != needle[1] || merged[i + 2] != needle[2] || merged[i + 3] != needle[3]) {
                    continue;
                }
                long addr = mergedStartAddress + i;
                hits.add(new IntScanHit(addr, String.format("0x%016X", addr), region.shortLabel(), value, hexContext(merged, i, 4, 32), List.of()));
            }

            tail = slice(merged, Math.max(0, merged.length - 3), merged.length);
            offsetInRegion += chunk.length;
        }
    }

    private List<IntScanHit> enrichIntHitsWithPointers(RandomAccessFile memFile,
                                                       List<MemoryRegion> regions,
                                                       List<IntScanHit> hits,
                                                       boolean anonymousWritableOnly,
                                                       boolean noExecOnly,
                                                       long maxPointerScanBytesPerRegion,
                                                       int maxPointerReferencesPerHit,
                                                       List<String> warnings) {
        Map<Long, List<PlayerPointerReference>> refsByHitAddress = new HashMap<>();
        for (IntScanHit h : hits) {
            refsByHitAddress.put(h.address(), new ArrayList<>());
        }

        long minScanBytes = Math.max(maxPointerScanBytesPerRegion, 8L);
        for (MemoryRegion region : regions) {
            if (!region.readable()) continue;
            if (anonymousWritableOnly && !region.anonymousWritable()) continue;
            if (noExecOnly && region.executable()) continue;
            scanRegionForPointers(memFile, region, minScanBytes, refsByHitAddress, maxPointerReferencesPerHit, warnings);
        }

        List<IntScanHit> enriched = new ArrayList<>(hits.size());
        for (IntScanHit h : hits) {
            List<PlayerPointerReference> refs = List.copyOf(refsByHitAddress.getOrDefault(h.address(), List.of()));
            enriched.add(new IntScanHit(h.address(), h.addressHex(), h.region(), h.value(), h.contextHex(), refs));
        }
        return enriched;
    }

    private void scanRegionForPattern(RandomAccessFile memFile,
                                      MemoryRegion region,
                                      List<Integer> pattern,
                                      int baseIndex,
                                      int maxHits,
                                      long maxBytesPerRegion,
                                      boolean unordered,
                                      String encodings,
                                      List<PatternScanHit> hits,
                                      List<String> warnings) {
        String enc = encodings == null ? "all" : encodings.trim().toLowerCase(Locale.ROOT);
        boolean doByte = enc.equals("all") || enc.contains("byte");
        boolean doU16 = enc.equals("all") || enc.contains("u16");
        boolean doU32 = enc.equals("all") || enc.contains("u32");

        // Try encodings that commonly show up in game structures:
        // - byte stride 1
        // - byte stride 2 (value every 2 bytes)
        // - byte stride 4 (value every 4 bytes, e.g. int32 aligned)
        // - u16 little endian (2 bytes per value), with common paddings
        // - u32 little endian (4 bytes per value), with common paddings
        if (doByte) {
            scanRegionForPatternByte(memFile, region, pattern, baseIndex, maxHits, maxBytesPerRegion, unordered, hits, warnings, 1);
            if (hits.size() >= maxHits) return;
            scanRegionForPatternByte(memFile, region, pattern, baseIndex, maxHits, maxBytesPerRegion, unordered, hits, warnings, 2);
            if (hits.size() >= maxHits) return;
            scanRegionForPatternByte(memFile, region, pattern, baseIndex, maxHits, maxBytesPerRegion, unordered, hits, warnings, 4);
            if (hits.size() >= maxHits) return;
        }
        if (doU32) {
            // Padding/stride variants. Many Unity/IL2CPP structs align ints on 4/8/16 byte boundaries.
            for (int stride : List.of(4, 8, 12, 16, 20, 24, 28, 32)) {
                scanRegionForPatternU32(memFile, region, pattern, baseIndex, maxHits, maxBytesPerRegion, unordered, hits, warnings, stride);
                if (hits.size() >= maxHits) return;
            }
        }
        if (doU16) {
            for (int stride : List.of(2, 4, 6, 8, 10, 12, 14, 16)) {
                scanRegionForPatternU16(memFile, region, pattern, baseIndex, maxHits, maxBytesPerRegion, unordered, hits, warnings, stride);
                if (hits.size() >= maxHits) return;
            }
        }
    }

    public PointerScanResult scanPointersTo(int pid,
                                            String target,
                                            int maxReferences,
                                            long maxBytesPerRegion,
                                            boolean anonymousWritableOnly,
                                            boolean noExecOnly,
                                            String regionStart,
                                            String regionEnd) {
        if (target == null || target.isBlank()) {
            throw new IllegalArgumentException("target is required");
        }
        if (maxReferences <= 0) {
            throw new IllegalArgumentException("maxReferences must be > 0");
        }
        if (maxBytesPerRegion <= 0) {
            throw new IllegalArgumentException("maxBytesPerRegion must be > 0");
        }

        long targetAddress = parseAddress(target);
        RunningProcess process = describeProcess(pid);
        List<MemoryRegion> regions = listMemoryRegions(process.pid());
        List<String> warnings = new ArrayList<>();

        Long restrictStart = null;
        Long restrictEnd = null;
        if (regionStart != null && !regionStart.isBlank()) restrictStart = parseAddress(regionStart);
        if (regionEnd != null && !regionEnd.isBlank()) restrictEnd = parseAddress(regionEnd);
        if (restrictStart != null && restrictEnd != null && restrictEnd < restrictStart) {
            throw new IllegalArgumentException("regionEnd must be >= regionStart");
        }

        Map<Long, List<PlayerPointerReference>> refsByTarget = new HashMap<>();
        refsByTarget.put(targetAddress, new ArrayList<>());

        long minScanBytes = Math.max(maxBytesPerRegion, 8L);
        int scannedRegions = 0;

        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            for (MemoryRegion region : regions) {
                if (!region.readable()) continue;
                if (anonymousWritableOnly && !region.anonymousWritable()) continue;
                if (noExecOnly && region.executable()) continue;
                if (restrictStart != null || restrictEnd != null) {
                    long rs = restrictStart == null ? Long.MIN_VALUE : restrictStart;
                    long re = restrictEnd == null ? Long.MAX_VALUE : restrictEnd;
                    if (region.endAddress() <= rs || region.startAddress() >= re) continue;
                }
                if (refsByTarget.get(targetAddress).size() >= maxReferences) break;
                scannedRegions++;
                scanRegionForPointers(memFile, region, minScanBytes, refsByTarget, maxReferences, warnings);
            }
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
        }

        List<PlayerPointerReference> refs = List.copyOf(refsByTarget.getOrDefault(targetAddress, List.of()));
        return new PointerScanResult(
                process.pid(),
                process.name(),
                process.command(),
                targetAddress,
                String.format("0x%016X", targetAddress),
                scannedRegions,
                refs,
                warnings
        );
    }

    public LvtpRunScanResult scanForLvtpRuns(int pid,
                                             int maxRuns,
                                             int minRunRecords,
                                             boolean anonymousWritableOnly,
                                             boolean noExecOnly,
                                             int maxRegions,
                                             long maxBytesPerRegion,
                                             String regionStart,
                                             String regionEnd) {
        if (maxRuns <= 0) throw new IllegalArgumentException("maxRuns must be > 0");
        if (minRunRecords <= 0) throw new IllegalArgumentException("minRunRecords must be > 0");
        if (maxRegions <= 0) throw new IllegalArgumentException("maxRegions must be > 0");
        if (maxBytesPerRegion <= 0) throw new IllegalArgumentException("maxBytesPerRegion must be > 0");

        RunningProcess process = describeProcess(pid);
        List<MemoryRegion> regions = listMemoryRegions(process.pid());
        List<String> warnings = new ArrayList<>();

        Long restrictStart = null;
        Long restrictEnd = null;
        if (regionStart != null && !regionStart.isBlank()) restrictStart = parseAddress(regionStart);
        if (regionEnd != null && !regionEnd.isBlank()) restrictEnd = parseAddress(regionEnd);
        if (restrictStart != null && restrictEnd != null && restrictEnd < restrictStart) {
            throw new IllegalArgumentException("regionEnd must be >= regionStart");
        }

        List<MemoryRegion> candidates = new ArrayList<>();
        for (MemoryRegion r : regions) {
            if (!r.readable()) continue;
            if (anonymousWritableOnly && !r.anonymousWritable()) continue;
            if (noExecOnly && r.executable()) continue;
            if (restrictStart != null || restrictEnd != null) {
                long rs = restrictStart == null ? Long.MIN_VALUE : restrictStart;
                long re = restrictEnd == null ? Long.MAX_VALUE : restrictEnd;
                if (r.endAddress() <= rs || r.startAddress() >= re) continue;
            }
            candidates.add(r);
        }
        candidates.sort((a, b) -> Long.compare((b.endAddress() - b.startAddress()), (a.endAddress() - a.startAddress())));
        if (candidates.size() > maxRegions) candidates = candidates.subList(0, maxRegions);

        List<LvtpRun> runs = new ArrayList<>();
        int scanned = 0;
        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            for (MemoryRegion region : candidates) {
                if (runs.size() >= maxRuns) break;
                scanned++;
                scanRegionForLvtpRuns(memFile, region, minRunRecords, maxBytesPerRegion, maxRuns, runs, warnings);
            }
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
        }

        runs.sort((a, b) -> Integer.compare(b.recordCount(), a.recordCount()));
        if (runs.size() > maxRuns) runs = runs.subList(0, maxRuns);

        return new LvtpRunScanResult(process.pid(), process.name(), process.command(), scanned, minRunRecords, runs, warnings);
    }

    public LvtpAttributesResult attributesFromBestLvtpRun(int pid,
                                                          boolean anonymousWritableOnly,
                                                          boolean noExecOnly,
                                                          int maxRegions,
                                                          long maxBytesPerRegion,
                                                          int minRunRecords,
                                                          String regionStart,
                                                          String regionEnd) {
        LvtpRunScanResult scan = scanForLvtpRuns(pid, 3, minRunRecords, anonymousWritableOnly, noExecOnly, maxRegions, maxBytesPerRegion, regionStart, regionEnd);
        if (scan.runs().isEmpty()) {
            throw new IllegalStateException("No LVTP run found (minRunRecords=" + minRunRecords + ")");
        }
        // Prefer the longest run; if tie, the first is fine.
        LvtpRun best = scan.runs().stream()
                .max(Comparator.comparingInt(LvtpRun::recordCount))
                .orElseThrow();
        return attributesFromLvtpRun(scan.pid(), scan.processName(), scan.command(), best);
    }

    public LvtpAttributesResult attributesFromLvtpRun(int pid, LvtpRun run) {
        RunningProcess process = describeProcess(pid);
        return attributesFromLvtpRun(process.pid(), process.name(), process.command(), run);
    }

    private LvtpAttributesResult attributesFromLvtpRun(int pid, String processName, String command, LvtpRun run) {
        Map<Integer, Integer> raw = new LinkedHashMap<>();
        for (LvtpRecord r : run.records()) {
            raw.put(r.id(), r.value());
        }

        Map<String, Integer> attrs = new LinkedHashMap<>();
        // Technical (confirmed via Crossing/Finishing/Dribbling diffs and UI screenshots)
        // Note: in FM26 we've observed Corners coming through as id 23 (not id 8).
        putIfPresent(raw, attrs, 23, "corners");
        putIfPresent(raw, attrs, 10, "crossing");
        putIfPresent(raw, attrs, 11, "dribbling");
        putIfPresent(raw, attrs, 12, "finishing");
        putIfPresent(raw, attrs, 13, "heading");
        putIfPresent(raw, attrs, 14, "longShots");
        putIfPresent(raw, attrs, 15, "longThrows");
        putIfPresent(raw, attrs, 16, "marking");
        putIfPresent(raw, attrs, 17, "passing");
        putIfPresent(raw, attrs, 18, "penaltyTaking");
        putIfPresent(raw, attrs, 19, "freeKickTaking");
        putIfPresent(raw, attrs, 20, "tackling");
        putIfPresent(raw, attrs, 21, "technique");
        putIfPresent(raw, attrs, 22, "firstTouch");

        // Mental
        putIfPresent(raw, attrs, 24, "aggression");
        putIfPresent(raw, attrs, 25, "anticipation");
        putIfPresent(raw, attrs, 26, "bravery");
        putIfPresent(raw, attrs, 36, "composure");
        putIfPresent(raw, attrs, 37, "concentration");
        putIfPresent(raw, attrs, 28, "decisions");
        putIfPresent(raw, attrs, 29, "determination");
        putIfPresent(raw, attrs, 30, "flair");
        putIfPresent(raw, attrs, 31, "leadership");
        putIfPresent(raw, attrs, 32, "offTheBall");
        putIfPresent(raw, attrs, 33, "positioning");
        putIfPresent(raw, attrs, 34, "teamwork");
        putIfPresent(raw, attrs, 27, "vision");
        putIfPresent(raw, attrs, 35, "workRate");

        // Physical
        putIfPresent(raw, attrs, 38, "acceleration");
        putIfPresent(raw, attrs, 39, "agility");
        putIfPresent(raw, attrs, 40, "balance");
        putIfPresent(raw, attrs, 41, "pace");
        putIfPresent(raw, attrs, 42, "stamina");
        putIfPresent(raw, attrs, 43, "strength");
        putIfPresent(raw, attrs, 44, "jumpingReach");
        putIfPresent(raw, attrs, 45, "naturalFitness");

        // Unknown/extra ids (keep them visible for reverse engineering)
        for (Map.Entry<Integer, Integer> e : raw.entrySet()) {
            int id = e.getKey();
            if (isMappedId(id)) continue;
            attrs.put(String.format("unknown_id_%02d", id), e.getValue());
        }

        return new LvtpAttributesResult(pid, processName, command, run.startHex(), run.region(), run.recordCount(), raw, attrs);
    }

    public Long findPlayerIdNear(int pid, long lvtpRunStart, String regionLabel, int windowBeforeBytes, int windowAfterBytes) {
        long[] range = parseRegionRange(regionLabel);
        if (range == null) return null;
        long regionStart = range[0];
        long regionEnd = range[1];

        long start = Math.max(regionStart, lvtpRunStart - (long) windowBeforeBytes);
        long end = Math.min(regionEnd, lvtpRunStart + (long) windowAfterBytes);
        long sizeL = end - start;
        if (sizeL <= 0) return null;
        if (sizeL > 2L * 1024 * 1024) {
            // keep bounded: caller should tune windows if they want more
            end = start + (2L * 1024 * 1024);
            sizeL = end - start;
        }
        int size = (int) sizeL;

        byte[] buf = new byte[size];
        int read;
        Path memPath = Path.of(PROC_ROOT, String.valueOf(pid), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            memFile.seek(start);
            read = memFile.read(buf);
        } catch (IOException e) {
            return null;
        }
        if (read <= 0) return null;
        if (read < buf.length) buf = Arrays.copyOf(buf, read);

        class Cand {
            int count;
            long minDist;
            Cand(long minDist) { this.count = 1; this.minDist = minDist; }
        }
        Map<Integer, Cand> cands = new HashMap<>();
        long runOff = lvtpRunStart - start;
        for (int off = 0; off + 4 <= buf.length; off += 4) {
            int v = (buf[off] & 0xFF)
                    | ((buf[off + 1] & 0xFF) << 8)
                    | ((buf[off + 2] & 0xFF) << 16)
                    | ((buf[off + 3] & 0xFF) << 24);
            if (v < 1_000_000 || v > 150_000_000) continue;
            long dist = Math.abs(runOff - off);
            Cand c = cands.get(v);
            if (c == null) {
                cands.put(v, new Cand(dist));
            } else {
                c.count++;
                if (dist < c.minDist) c.minDist = dist;
            }
        }
        if (cands.isEmpty()) return null;

        long bestScore = Long.MIN_VALUE;
        int bestVal = -1;
        for (Map.Entry<Integer, Cand> e : cands.entrySet()) {
            Cand c = e.getValue();
            // Score: favor multiple sightings and proximity.
            long score = (long) c.count * 100_000L - (c.minDist / 16);
            if (score > bestScore) {
                bestScore = score;
                bestVal = e.getKey();
            }
        }
        return bestVal > 0 ? (long) bestVal : null;
    }

    public LvtpPlayerIdResult findPlayerIdForBestLvtpRun(int pid,
                                                         boolean anonymousWritableOnly,
                                                         boolean noExecOnly,
                                                         int maxRegions,
                                                         long maxBytesPerRegion,
                                                         int minRunRecords,
                                                         int windowBeforeBytes,
                                                         int windowAfterBytes,
                                                         String regionStart,
                                                         String regionEnd) {
        LvtpRunScanResult scan = scanForLvtpRuns(pid, 3, minRunRecords, anonymousWritableOnly, noExecOnly, maxRegions, maxBytesPerRegion, regionStart, regionEnd);
        if (scan.runs().isEmpty()) {
            throw new IllegalStateException("No LVTP run found (minRunRecords=" + minRunRecords + ")");
        }
        LvtpRun best = scan.runs().stream()
                .max(Comparator.comparingInt(LvtpRun::recordCount))
                .orElseThrow();

        Long found = findPlayerIdNear(scan.pid(), best.startAddress(), best.region(), windowBeforeBytes, windowAfterBytes);
        Integer playerId = found == null ? null : (int) (long) found;
        return new LvtpPlayerIdResult(scan.pid(), scan.processName(), scan.command(), best.startHex(), best.region(), best.recordCount(), playerId);
    }

    public ActiveLvtpPlayerResult findActivePlayerFromBestLvtpRun(int pid,
                                                                  boolean anonymousWritableOnly,
                                                                  boolean noExecOnly,
                                                                  int maxRegions,
                                                                  long maxBytesPerRegion,
                                                                  int minRunRecords,
                                                                  int maxPointerReferences,
                                                                  long maxPointerScanBytesPerRegion,
                                                                  String pointerRegionStart,
                                                                  String pointerRegionEnd,
                                                                  int maxDepth,
                                                                  int maxVisited) {
        LvtpRunScanResult scan = scanForLvtpRuns(pid, 1, minRunRecords, anonymousWritableOnly, noExecOnly, maxRegions, maxBytesPerRegion, null, null);
        if (scan.runs().isEmpty()) {
            throw new IllegalStateException("No LVTP run found (minRunRecords=" + minRunRecords + ")");
        }
        LvtpRun run = scan.runs().getFirst();

        List<String> warnings = new ArrayList<>(scan.warnings());
        RunningProcess process = new RunningProcess(scan.pid(), scan.processName(), scan.command());
        List<MemoryRegion> regions = listMemoryRegions(process.pid());

        long uiStart = parseAddress(pointerRegionStart);
        long uiEnd = parseAddress(pointerRegionEnd);
        if (uiEnd <= uiStart) {
            throw new IllegalArgumentException("pointerRegionEnd must be > pointerRegionStart");
        }

        MemoryRegion runRegion = findRegionContaining(regions, run.startAddress());
        long runEndExclusive = runRegion == null ? Long.MAX_VALUE : runRegion.endAddress();

        // Build a small list of LVTP anchor addresses that are likely to be referenced by UI/view-model objects.
        //
        // In practice we've observed pointers that land "inside" the LVTP run, not necessarily on a record boundary.
        // So we try a handful of offsets near the start of the run plus a few record-aligned candidates.
        List<Long> anchors = new ArrayList<>();
        long[] commonOffsets = new long[]{
                0x250, 0x252, 0x260, 0x300, 0x400, 0x500, 0x600, 0x800, 0xA00
        };
        for (long off : commonOffsets) {
            long a = run.startAddress() + off;
            if (a > run.startAddress() && a < runEndExclusive) anchors.add(a);
        }
        int anchorCount = Math.min(6, Math.max(1, run.recordCount()));
        for (int i = 0; i < anchorCount; i++) {
            long a = run.startAddress() + (long) i * LVTP_RECORD_LEN + 3L;
            if (a > run.startAddress() && a < runEndExclusive) anchors.add(a);
        }

        // Find any pointer reference in the UI region that points into this LVTP run.
        String chosenAnchorHex = null;
        Long uiRefAddr = null;
        for (long anchor : anchors) {
            PointerScanResult refs = scanPointersTo(
                    process.pid(),
                    String.format("0x%016X", anchor),
                    maxPointerReferences,
                    maxPointerScanBytesPerRegion,
                    true,
                    true,
                    pointerRegionStart,
                    pointerRegionEnd
            );
            warnings.addAll(refs.warnings());
            if (!refs.references().isEmpty()) {
                chosenAnchorHex = String.format("0x%016X", anchor);
                // Prefer the first reference; the scan already stops when capacity is reached.
                uiRefAddr = refs.references().getFirst().address();
                break;
            }
        }

        if (uiRefAddr == null) {
            return new ActiveLvtpPlayerResult(
                    process.pid(),
                    process.name(),
                    process.command(),
                    run.startHex(),
                    run.region(),
                    run.recordCount(),
                    chosenAnchorHex,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    warnings
            );
        }

        // Enumerate player nodes (id + first/last name) so we can resolve playerIds found in UI objects
        // without requiring a direct pointer to the player-node struct.
        Map<Integer, EnumeratedPlayer> playerById = new HashMap<>();
        try {
            EnumeratePlayersResult enumRes = enumeratePlayersInRegion(
                    process.pid(),
                    "0x7E5D0000",
                    "0x7F5A0000",
                    250_000,
                    false,
                    true,
                    false,
                    1,
                    0,
                    0,
                    0
            );
            warnings.addAll(enumRes.warnings());
            for (EnumeratedPlayer p : enumRes.players()) {
                playerById.putIfAbsent(p.playerId(), p);
            }
        } catch (Exception e) {
            warnings.add("Could not enumerate player nodes for id->name mapping: " + e.getMessage());
        }

        // Candidate roots: align the pointer location down to common object boundaries.
        List<Long> roots = List.of(
                uiRefAddr & ~0xFFL,
                uiRefAddr & ~0x3FFL,
                uiRefAddr & ~0xFFFL
        );

        // BFS through pointers: starting in the UI region, try to reach a player-node struct in the 0x7E.. region.
        record Q(long addr, int depth) {}

        ActivePlayerNode found = null;
        Long chosenUiRoot = null;
        Long uiIdHitAddr = null;
        Integer uiIdHitOff = null;

        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            for (long root : roots) {
                if (root == 0) continue;
                Set<Long> visited = new LinkedHashSet<>();
                ArrayDeque<Q> q = new ArrayDeque<>();
                q.add(new Q(root, 0));
                visited.add(root);

                while (!q.isEmpty() && visited.size() < maxVisited) {
                    Q cur = q.removeFirst();
                    long addr = cur.addr();
                    int depth = cur.depth();

                    // If we're in the player-tree region, check for a player-node struct near this address.
                    if (addr >= 0x7E000000L && addr < 0x80000000L) {
                        ActivePlayerNode n = tryReadPlayerNode(memFile, regions, addr, warnings);
                        if (n != null) {
                            found = n;
                            chosenUiRoot = root;
                            break;
                        }
                    }

                    if (depth >= maxDepth) continue;

                    // Follow pointers from this address (small window).
                    byte[] buf = new byte[2048];
                    int read;
                    try {
                        memFile.seek(addr);
                        read = memFile.read(buf);
                        if (read <= 0) continue;
                        if (read < buf.length) buf = Arrays.copyOf(buf, read);
                    } catch (IOException e) {
                        continue;
                    }

                    // Heuristic: UI/view-model objects often embed the playerId as a 32-bit int.
                    if (!playerById.isEmpty()) {
                        for (int off = 0; off + 4 <= buf.length; off += 4) {
                            int v = readInt32LittleEndian(buf, off);
                            EnumeratedPlayer ep = playerById.get(v);
                            if (ep != null) {
                                found = new ActivePlayerNode(ep.structAddress(), ep.playerId(), ep.firstName(), ep.lastName());
                                chosenUiRoot = root;
                                uiIdHitAddr = addr;
                                uiIdHitOff = off;
                                break;
                            }
                        }
                        if (found != null) break;
                    }

                    for (int off = 0; off + 7 < buf.length; off += 8) {
                        long target = readLongLittleEndian(buf, off);
                        if (target == 0) continue;
                        if (visited.contains(target)) continue;
                        MemoryRegion tr = findRegionContaining(regions, target);
                        if (tr == null || !tr.readable()) continue;
                        if (noExecOnly && tr.executable()) continue;

                        // Keep traversal focused: UI region and player tree region.
                        boolean inUi = target >= uiStart && target < uiEnd;
                        boolean inTree = target >= 0x7E000000L && target < 0x80000000L;
                        boolean ok = inUi || inTree;
                        if (!ok) continue;

                        visited.add(target);
                        q.addLast(new Q(target, depth + 1));
                        if (visited.size() >= maxVisited) break;
                    }
                }
                if (found != null) break;
            }
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
        }

        return new ActiveLvtpPlayerResult(
                process.pid(),
                process.name(),
                process.command(),
                run.startHex(),
                run.region(),
                run.recordCount(),
                chosenAnchorHex,
                String.format("0x%016X", uiRefAddr),
                chosenUiRoot == null ? null : String.format("0x%016X", chosenUiRoot),
                uiIdHitAddr == null ? null : String.format("0x%016X", uiIdHitAddr),
                uiIdHitOff,
                found == null ? null : String.format("0x%016X", found.address),
                found == null ? null : found.playerId,
                found == null ? null : found.firstName,
                found == null ? null : found.lastName,
                warnings
        );
    }

    private ActivePlayerNode tryReadPlayerNode(RandomAccessFile memFile, List<MemoryRegion> regions, long near, List<String> warnings) {
        // Scan a small neighborhood to find the exact struct start.
        for (long base = near - 0x100; base <= near + 0x100; base += 8) {
            if (base < 0) continue;
            try {
                byte[] buf = new byte[0x60];
                memFile.seek(base);
                int read = memFile.read(buf);
                if (read < 0x38) continue;
                if (read < buf.length) buf = Arrays.copyOf(buf, read);

                int playerId = readInt32LittleEndian(buf, 0x20);
                if (playerId < 1_000_000 || playerId > 150_000_000) continue;

                long pFirst = readLongLittleEndian(buf, 0x28);
                long pLast = readLongLittleEndian(buf, 0x30);
                if (!isLikelyPointer(regions, pFirst, false, true)) continue;
                if (!isLikelyPointer(regions, pLast, false, true)) continue;
                String first = readNameString(memFile, pFirst, 32, warnings);
                String last = readNameString(memFile, pLast, 32, warnings);
                if (first == null || last == null) continue;
                if (!isPlausibleFirstName(first) || !isPlausibleLastName(last, first)) continue;

                return new ActivePlayerNode(base, playerId, first, last);
            } catch (IOException ignored) {
                // keep scanning
            }
        }
        return null;
    }

    private long[] parseRegionRange(String regionLabel) {
        if (regionLabel == null) return null;
        String s = regionLabel.trim();
        int sp = s.indexOf(' ');
        String first = sp < 0 ? s : s.substring(0, sp);
        int dash = first.indexOf('-');
        if (dash <= 0) return null;
        try {
            long start = parseAddress(first.substring(0, dash));
            long end = parseAddress(first.substring(dash + 1));
            if (end <= start) return null;
            return new long[]{start, end};
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isMappedId(int id) {
        // Keep in sync with attributesFromBestLvtpRun mappings.
        return (id >= 8 && id <= 22)
                || id == 23
                || (id >= 24 && id <= 37)
                || (id >= 38 && id <= 45);
    }

    private void putIfPresent(Map<Integer, Integer> raw, Map<String, Integer> attrs, int id, String key) {
        Integer v = raw.get(id);
        if (v != null) attrs.put(key, v);
    }

    private void scanRegionForLvtpRuns(RandomAccessFile memFile,
                                       MemoryRegion region,
                                       int minRunRecords,
                                       long maxBytesPerRegion,
                                       int maxRuns,
                                       List<LvtpRun> out,
                                       List<String> warnings) {
        long regionSize = region.endAddress() - region.startAddress();
        long maxScan = Math.min(regionSize, maxBytesPerRegion);
        long offsetInRegion = 0;
        byte[] tail = new byte[0];
        // Avoid duplicates: we may encounter the same run start across chunk boundaries or via overlap.
        Set<Long> seenRunStarts = new java.util.HashSet<>();
        Set<Long> seenParsedRunStarts = new java.util.HashSet<>();

        // Scan for any LVTP record core (`lvtp`), then expand to a contiguous record run.
        // The original approach scanned only for record-id 0, which can miss runs where the
        // first in-memory record isn't id 0 (or where ids are non-consecutive).
        while (offsetInRegion < maxScan && out.size() < maxRuns) {
            int toRead = (int) Math.min(CHUNK_SIZE, maxScan - offsetInRegion);
            byte[] chunk = new byte[toRead];
            long absoluteStart = region.startAddress() + offsetInRegion;
            try {
                memFile.seek(absoluteStart);
                int bytesRead = memFile.read(chunk);
                if (bytesRead <= 0) break;
                if (bytesRead < toRead) {
                    chunk = Arrays.copyOf(chunk, bytesRead);
                }
            } catch (IOException e) {
                warnings.add("LVTP scan read failed at 0x" + Long.toHexString(absoluteStart) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            byte[] merged = concat(tail, chunk);
            long mergedStartAddress = absoluteStart - tail.length;

            int idx = 0;
            while (idx >= 0 && idx + LVTP_CORE.length <= merged.length && out.size() < maxRuns) {
                idx = indexOf(merged, LVTP_CORE, idx);
                if (idx < 0) break;

                // LVTP_CORE sits at recordStart+3.
                int recordStart = idx - 3;
                if (recordStart < 0) {
                    idx = idx + 1;
                    continue;
                }
                // Validate record header bytes 01 11 <id>.
                if ((merged[recordStart] & 0xFF) != 0x01 || (merged[recordStart + 1] & 0xFF) != 0x11) {
                    idx = idx + 1;
                    continue;
                }

                long absoluteHeader = mergedStartAddress + recordStart;
                if (!seenRunStarts.add(absoluteHeader)) {
                    idx = idx + 1;
                    continue;
                }
                LvtpRun run = tryParseLvtpRun(memFile, region, absoluteHeader, minRunRecords, warnings);
                if (run != null) {
                    if (seenParsedRunStarts.add(run.startAddress())) {
                        out.add(run);
                    }
                    if (out.size() >= maxRuns) break;
                }
                idx = idx + 1;
            }

            int keepTail = Math.max(LVTP_RECORD_LEN * 2, LVTP_CORE.length + 16);
            if (keepTail > merged.length) keepTail = merged.length;
            tail = Arrays.copyOfRange(merged, merged.length - keepTail, merged.length);
            offsetInRegion += chunk.length;
        }
    }

    private LvtpRun tryParseLvtpRun(RandomAccessFile memFile,
                                    MemoryRegion region,
                                    long absoluteHeaderAddress,
                                    int minRunRecords,
                                    List<String> warnings) {
        // Read a small window and try to backtrack to the start of an increasing-id run.
        // The full Timber run is ~1.6 KiB; 16 KiB is enough for backtracking and forward parsing.
        byte[] buf = new byte[16 * 1024];
        int read;
        try {
            long start = Math.max(region.startAddress(), absoluteHeaderAddress - (8L * LVTP_RECORD_LEN));
            memFile.seek(start);
            read = memFile.read(buf);
            if (read <= 0) return null;
            if (read < buf.length) buf = Arrays.copyOf(buf, read);

            int baseOff = (int) (absoluteHeaderAddress - start);
            int headerOff = baseOff;
            LvtpRecord first = parseLvtpRecord(buf, headerOff);
            if (first == null) return null;

            // Backtrack while possible.
            // We previously required consecutive ids; that turned out brittle.
            // Instead, treat a "run" as a contiguous block of valid LVTP records.
            int curOff = headerOff;
            while (true) {
                int prevOff = curOff - LVTP_RECORD_LEN;
                if (prevOff < 0) break;
                LvtpRecord prev = parseLvtpRecord(buf, prevOff);
                if (prev == null) break;
                curOff = prevOff;
            }

            // Forward parse.
            List<LvtpRecord> records = new ArrayList<>();
            int off = curOff;
            while (off + LVTP_RECORD_LEN <= buf.length) {
                LvtpRecord rec = parseLvtpRecord(buf, off);
                if (rec == null) break;
                records.add(rec);
                off += LVTP_RECORD_LEN;
                // Hard stop; prevents runaway parsing if we ever hit a long unrelated sequence.
                if (records.size() >= 512) break;
            }

            if (records.size() < minRunRecords) return null;
            long runStartAbs = start + curOff;
            return new LvtpRun(runStartAbs, String.format("0x%016X", runStartAbs), region.shortLabel(), records.size(), records);
        } catch (IOException e) {
            warnings.add("LVTP parse read failed at 0x" + String.format("%016X", absoluteHeaderAddress) + " in region " + region.shortLabel() + ": " + e.getMessage());
            return null;
        }
    }

    private LvtpRecord parseLvtpRecord(byte[] buf, int off) {
        if (off < 0 || off + LVTP_RECORD_LEN > buf.length) return null;
        if ((buf[off] & 0xFF) != 0x01) return null;
        if ((buf[off + 1] & 0xFF) != 0x11) return null;
        int id = buf[off + 2] & 0xFF;
        int coreOff = off + 3;
        for (int i = 0; i < LVTP_CORE.length; i++) {
            if (buf[coreOff + i] != LVTP_CORE[i]) return null;
        }
        int pos = coreOff + LVTP_CORE.length;
        List<Integer> values = new ArrayList<>(3);
        for (int i = 0; i < 3; i++) {
            if ((buf[pos] & 0xFF) != 0x01 || (buf[pos + 1] & 0xFF) != 0x11) return null;
            values.add(buf[pos + 2] & 0xFF);
            // pos+3..pos+6 is a 4-byte key (often ASCII); ignore it.
            pos += 7;
        }
        int v = values.getFirst();
        return new LvtpRecord(id, String.format("0x%02X", id), List.copyOf(values), v);
    }

    private int indexOf(byte[] haystack, byte[] needle, int fromIndex) {
        if (needle.length == 0) return fromIndex;
        if (fromIndex < 0) fromIndex = 0;
        int max = haystack.length - needle.length;
        for (int i = fromIndex; i <= max; i++) {
            boolean ok = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return i;
        }
        return -1;
    }

    private void scanRegionForPatternByte(RandomAccessFile memFile,
                                          MemoryRegion region,
                                          List<Integer> pattern,
                                          int baseIndex,
                                          int maxHits,
                                          long maxBytesPerRegion,
                                          boolean unordered,
                                          List<PatternScanHit> hits,
                                          List<String> warnings,
                                          int stride) {
        long regionSize = region.endAddress() - region.startAddress();
        long maxScan = Math.min(regionSize, maxBytesPerRegion);
        long offsetInRegion = 0;
        int patternBytes = pattern.size() * stride;
        byte[] tail = new byte[0];

        while (offsetInRegion < maxScan && hits.size() < maxHits) {
            int toRead = (int) Math.min(CHUNK_SIZE, maxScan - offsetInRegion);
            byte[] chunk = new byte[toRead];
            long absoluteStart = region.startAddress() + offsetInRegion;
            try {
                memFile.seek(absoluteStart);
                int bytesRead = memFile.read(chunk);
                if (bytesRead <= 0) break;
                if (bytesRead < toRead) {
                    byte[] resized = new byte[bytesRead];
                    System.arraycopy(chunk, 0, resized, 0, bytesRead);
                    chunk = resized;
                }
            } catch (IOException e) {
                warnings.add("Pattern scan read failed at 0x" + Long.toHexString(absoluteStart) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            byte[] merged = concat(tail, chunk);
            long mergedStartAddress = absoluteStart - tail.length;

            for (int i = 0; i + patternBytes <= merged.length && hits.size() < maxHits; i++) {
                if (!matchesPatternByte(merged, i, pattern, stride, unordered)) continue;
                long matchAddress = mergedStartAddress + i;
                long blockStart = matchAddress - ((long) baseIndex * stride);
                PatternScanHit hit = buildPatternHit(memFile, region, matchAddress, blockStart, "byte", stride, baseIndex, warnings);
                if (hit != null) hits.add(hit);
            }

            int keepTail = Math.max(patternBytes - 1, 0);
            if (keepTail > 0) {
                int start = Math.max(0, merged.length - keepTail);
                tail = new byte[merged.length - start];
                System.arraycopy(merged, start, tail, 0, tail.length);
            }
            offsetInRegion += chunk.length;
        }
    }

    private boolean matchesPatternByte(byte[] buf, int offset, List<Integer> pattern, int stride, boolean unordered) {
        if (!unordered) {
            for (int i = 0; i < pattern.size(); i++) {
                int want = pattern.get(i);
                int got = buf[offset + (i * stride)] & 0xFF;
                if (got != want) return false;
            }
            return true;
        }
        int n = pattern.size();
        int[] want = new int[n];
        int[] got = new int[n];
        for (int i = 0; i < n; i++) {
            want[i] = pattern.get(i);
            got[i] = buf[offset + (i * stride)] & 0xFF;
        }
        java.util.Arrays.sort(want);
        java.util.Arrays.sort(got);
        for (int i = 0; i < n; i++) {
            if (want[i] != got[i]) return false;
        }
        return true;
    }

    private void scanRegionForPatternU16(RandomAccessFile memFile,
                                         MemoryRegion region,
                                         List<Integer> pattern,
                                         int baseIndex,
                                         int maxHits,
                                         long maxBytesPerRegion,
                                         boolean unordered,
                                         List<PatternScanHit> hits,
                                         List<String> warnings,
                                         int strideBytes) {
        long regionSize = region.endAddress() - region.startAddress();
        long maxScan = Math.min(regionSize, maxBytesPerRegion);
        long offsetInRegion = 0;
        int patternSpan = Math.max(0, (pattern.size() - 1) * strideBytes) + 2;
        byte[] tail = new byte[0];

        while (offsetInRegion < maxScan && hits.size() < maxHits) {
            int toRead = (int) Math.min(CHUNK_SIZE, maxScan - offsetInRegion);
            byte[] chunk = new byte[toRead];
            long absoluteStart = region.startAddress() + offsetInRegion;
            try {
                memFile.seek(absoluteStart);
                int bytesRead = memFile.read(chunk);
                if (bytesRead <= 0) break;
                if (bytesRead < toRead) {
                    byte[] resized = new byte[bytesRead];
                    System.arraycopy(chunk, 0, resized, 0, bytesRead);
                    chunk = resized;
                }
            } catch (IOException e) {
                warnings.add("Pattern scan(u16) read failed at 0x" + Long.toHexString(absoluteStart) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            byte[] merged = concat(tail, chunk);
            long mergedStartAddress = absoluteStart - tail.length;

            for (int i = 0; i + patternSpan <= merged.length && hits.size() < maxHits; i += 2) {
                if (!matchesPatternU16(merged, i, pattern, unordered, strideBytes)) continue;
                long matchAddress = mergedStartAddress + i;
                long blockStart = matchAddress - ((long) baseIndex * strideBytes);
                PatternScanHit hit = buildPatternHit(memFile, region, matchAddress, blockStart, "u16_le", strideBytes, baseIndex, warnings);
                if (hit != null) hits.add(hit);
            }

            int keepTail = Math.max(patternSpan - 1, 0);
            if (keepTail > 0) {
                int start = Math.max(0, merged.length - keepTail);
                tail = new byte[merged.length - start];
                System.arraycopy(merged, start, tail, 0, tail.length);
            }
            offsetInRegion += chunk.length;
        }
    }

    private boolean matchesPatternU16(byte[] buf, int offset, List<Integer> pattern, boolean unordered, int strideBytes) {
        if (!unordered) {
            for (int i = 0; i < pattern.size(); i++) {
                int want = pattern.get(i);
                int off = offset + (i * strideBytes);
                int got = (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8);
                if (got != want) return false;
            }
            return true;
        }
        int n = pattern.size();
        int[] want = new int[n];
        int[] got = new int[n];
        for (int i = 0; i < n; i++) {
            want[i] = pattern.get(i);
            int off = offset + (i * strideBytes);
            got[i] = (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8);
        }
        java.util.Arrays.sort(want);
        java.util.Arrays.sort(got);
        for (int i = 0; i < n; i++) {
            if (want[i] != got[i]) return false;
        }
        return true;
    }

    private void scanRegionForPatternU32(RandomAccessFile memFile,
                                         MemoryRegion region,
                                         List<Integer> pattern,
                                         int baseIndex,
                                         int maxHits,
                                         long maxBytesPerRegion,
                                         boolean unordered,
                                         List<PatternScanHit> hits,
                                         List<String> warnings,
                                         int strideBytes) {
        long regionSize = region.endAddress() - region.startAddress();
        long maxScan = Math.min(regionSize, maxBytesPerRegion);
        long offsetInRegion = 0;
        int patternSpan = Math.max(0, (pattern.size() - 1) * strideBytes) + 4;
        byte[] tail = new byte[0];

        while (offsetInRegion < maxScan && hits.size() < maxHits) {
            int toRead = (int) Math.min(CHUNK_SIZE, maxScan - offsetInRegion);
            byte[] chunk = new byte[toRead];
            long absoluteStart = region.startAddress() + offsetInRegion;
            try {
                memFile.seek(absoluteStart);
                int bytesRead = memFile.read(chunk);
                if (bytesRead <= 0) break;
                if (bytesRead < toRead) {
                    byte[] resized = new byte[bytesRead];
                    System.arraycopy(chunk, 0, resized, 0, bytesRead);
                    chunk = resized;
                }
            } catch (IOException e) {
                warnings.add("Pattern scan(u32) read failed at 0x" + Long.toHexString(absoluteStart) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            byte[] merged = concat(tail, chunk);
            long mergedStartAddress = absoluteStart - tail.length;

            for (int i = 0; i + patternSpan <= merged.length && hits.size() < maxHits; i += 4) {
                if (!matchesPatternU32(merged, i, pattern, unordered, strideBytes)) continue;
                long matchAddress = mergedStartAddress + i;
                long blockStart = matchAddress - ((long) baseIndex * strideBytes);
                PatternScanHit hit = buildPatternHit(memFile, region, matchAddress, blockStart, "u32_le", strideBytes, baseIndex, warnings);
                if (hit != null) hits.add(hit);
            }

            int keepTail = Math.max(patternSpan - 1, 0);
            if (keepTail > 0) {
                int start = Math.max(0, merged.length - keepTail);
                tail = new byte[merged.length - start];
                System.arraycopy(merged, start, tail, 0, tail.length);
            }
            offsetInRegion += chunk.length;
        }
    }

    private boolean matchesPatternU32(byte[] buf, int offset, List<Integer> pattern, boolean unordered, int strideBytes) {
        int n = pattern.size();
        if (!unordered) {
            for (int i = 0; i < n; i++) {
                int want = pattern.get(i);
                int off = offset + (i * strideBytes);
                long got = ((long) buf[off] & 0xFF)
                        | (((long) buf[off + 1] & 0xFF) << 8)
                        | (((long) buf[off + 2] & 0xFF) << 16)
                        | (((long) buf[off + 3] & 0xFF) << 24);
                if (got != (want & 0xFFFFFFFFL)) return false;
            }
            return true;
        }
        int[] want = new int[n];
        int[] got = new int[n];
        for (int i = 0; i < n; i++) {
            want[i] = pattern.get(i);
            int off = offset + (i * strideBytes);
            got[i] = (buf[off] & 0xFF)
                    | ((buf[off + 1] & 0xFF) << 8)
                    | ((buf[off + 2] & 0xFF) << 16)
                    | ((buf[off + 3] & 0xFF) << 24);
        }
        java.util.Arrays.sort(want);
        java.util.Arrays.sort(got);
        for (int i = 0; i < n; i++) {
            if (want[i] != got[i]) return false;
        }
        return true;
    }

    private PatternScanHit buildPatternHit(RandomAccessFile memFile,
                                           MemoryRegion region,
                                           long matchAddress,
                                           long blockStartAddress,
                                           String encoding,
                                           int stride,
                                           int baseIndex,
                                           List<String> warnings) {
        // Read enough bytes to decode 36 values from blockStart.
        int bytes = switch (encoding) {
            case "u16_le" -> Math.max(0, (36 - 1) * stride) + 2;
            case "u32_le" -> Math.max(0, (36 - 1) * stride) + 4;
            default -> Math.max(0, (36 - 1) * stride) + 1;
        };
        byte[] window = readWindow(memFile, blockStartAddress, bytes, warnings);
        if (window.length < bytes) return null;
        List<Integer> values36 = decode36(window, encoding, stride);
        Map<String, Integer> attrs = toOutfieldAttributeMap(values36);
        return new PatternScanHit(
                matchAddress,
                String.format("0x%016X", matchAddress),
                region.shortLabel(),
                encoding,
                stride,
                baseIndex,
                blockStartAddress,
                String.format("0x%016X", blockStartAddress),
                values36,
                attrs
        );
    }

    private List<Integer> decode36(byte[] window, String encoding, int stride) {
        List<Integer> out = new ArrayList<>(36);
        if (encoding.equals("u16_le")) {
            for (int i = 0; i < 36; i++) {
                int off = i * stride;
                int v = (window[off] & 0xFF) | ((window[off + 1] & 0xFF) << 8);
                out.add(v);
            }
            return out;
        }
        if (encoding.equals("u32_le")) {
            for (int i = 0; i < 36; i++) {
                int off = i * stride;
                int v = (window[off] & 0xFF)
                        | ((window[off + 1] & 0xFF) << 8)
                        | ((window[off + 2] & 0xFF) << 16)
                        | ((window[off + 3] & 0xFF) << 24);
                out.add(v);
            }
            return out;
        }
        for (int i = 0; i < 36; i++) {
            out.add(window[i * stride] & 0xFF);
        }
        return out;
    }

    public List<RunningProcess> listProcesses(String nameFilter) {
        String normalizedFilter = nameFilter == null ? "" : nameFilter.toLowerCase(Locale.ROOT);
        List<RunningProcess> processes = new ArrayList<>();
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(Path.of(PROC_ROOT), this::isPidDirectory)) {
            for (Path pidPath : dirStream) {
                int pid;
                try {
                    pid = Integer.parseInt(pidPath.getFileName().toString());
                } catch (NumberFormatException ignored) {
                    continue;
                }

                String comm = readProcFile(pidPath.resolve("comm")).trim();
                String cmdline = readCmdline(pidPath.resolve("cmdline"));
                String haystack = (comm + " " + cmdline).toLowerCase(Locale.ROOT);
                if (!normalizedFilter.isBlank() && !haystack.contains(normalizedFilter)) {
                    continue;
                }
                processes.add(new RunningProcess(pid, comm, cmdline));
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read /proc for running processes", e);
        }

        processes.sort(Comparator.comparingInt(RunningProcess::pid));
        return processes;
    }

    public RunningProcess resolveProcess(String processHint) {
        String hint = processHint == null || processHint.isBlank() ? "football" : processHint;
        if (isNumeric(hint)) {
            return describeProcess(Integer.parseInt(hint));
        }
        List<RunningProcess> matches = listProcesses(hint);
        if (matches.isEmpty()) {
            throw new IllegalArgumentException("No process found matching hint: " + hint);
        }
        return matches.stream()
                .max(Comparator.comparingInt(p -> processScore(p, hint)))
                .orElse(matches.getFirst());
    }

    public List<MemoryRegion> listMemoryRegions(int pid) {
        Path mapsPath = Path.of(PROC_ROOT, String.valueOf(pid), "maps");
        List<MemoryRegion> regions = new ArrayList<>();
        List<String> lines;
        try {
            lines = Files.readAllLines(mapsPath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read maps for pid " + pid + ". Make sure the process exists and permissions allow access.", e);
        }

        for (String line : lines) {
            Optional<MemoryRegion> parsed = parseRegion(line);
            parsed.ifPresent(regions::add);
        }
        return regions;
    }

    public MemoryDump dumpMemory(int pid, String addressHex, int size) {
        long address = parseAddress(addressHex);
        return dumpMemory(pid, address, size);
    }

    public MemoryDumpFile dumpMemoryToFile(int pid, String addressHex, int size, String outPath) {
        long address = parseAddress(addressHex);
        if (size <= 0) {
            throw new IllegalArgumentException("size must be > 0");
        }
        if (size > MAX_DUMP_FILE_BYTES) {
            throw new IllegalArgumentException("size must be <= " + MAX_DUMP_FILE_BYTES + " bytes");
        }
        String path = sanitizeTmpPath(outPath);

        Path memPath = Path.of(PROC_ROOT, String.valueOf(pid), "mem");
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }

        int totalRead = 0;
        byte[] buf = new byte[Math.min(CHUNK_SIZE, size)];
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r");
             OutputStream os = Files.newOutputStream(Path.of(path),
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            memFile.seek(address);
            int remaining = size;
            while (remaining > 0) {
                int toRead = Math.min(buf.length, remaining);
                int read = memFile.read(buf, 0, toRead);
                if (read <= 0) break;
                os.write(buf, 0, read);
                md.update(buf, 0, read);
                totalRead += read;
                remaining -= read;
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to dump " + memPath + " at " + String.format("0x%016X", address) + ": " + e.getMessage(), e);
        }

        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return new MemoryDumpFile(pid, address, String.format("0x%016X", address), totalRead, path, sb.toString());
    }

    public MemoryDump dumpMemory(int pid, long address, int size) {
        if (size <= 0) {
            throw new IllegalArgumentException("size must be > 0");
        }
        int cappedSize = Math.min(size, 1024 * 1024); // hard cap 1MB
        Path memPath = Path.of(PROC_ROOT, String.valueOf(pid), "mem");
        byte[] buf = new byte[cappedSize];
        int read;
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            memFile.seek(address);
            read = memFile.read(buf);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read " + memPath + " at " + String.format("0x%016X", address) + ": " + e.getMessage(), e);
        }
        if (read <= 0) {
            read = 0;
            buf = new byte[0];
        } else if (read < buf.length) {
            byte[] resized = new byte[read];
            System.arraycopy(buf, 0, resized, 0, read);
            buf = resized;
        }

        String b64 = Base64.getEncoder().encodeToString(buf);
        String hexPreview = hexContext(buf, 0, 0, Math.min(256, buf.length));
        return new MemoryDump(pid, address, String.format("0x%016X", address), read, b64, hexPreview);
    }

    public SnapshotInfo snapshotWindow(int pid, String addressHex, int size, String tag) {
        if (tag == null || tag.isBlank()) {
            throw new IllegalArgumentException("tag is required");
        }
        String t = tag.trim();
        if (t.length() > 80) {
            throw new IllegalArgumentException("tag must be <= 80 chars");
        }
        long address = parseAddress(addressHex);
        if (size <= 0) {
            throw new IllegalArgumentException("size must be > 0");
        }
        if (size > MAX_SNAPSHOT_BYTES) {
            throw new IllegalArgumentException("size must be <= " + MAX_SNAPSHOT_BYTES + " bytes");
        }

        byte[] buf = readMemoryBytes(pid, address, size);
        String sha = sha256Hex(buf);
        Snapshot snap = new Snapshot(pid, address, buf.length, buf, sha);
        snapshots.put(t, snap);
        synchronized (snapshotFifo) {
            snapshotFifo.remove(t);
            snapshotFifo.addLast(t);
            while (snapshotFifo.size() > MAX_SNAPSHOTS) {
                String evict = snapshotFifo.removeFirst();
                snapshots.remove(evict);
            }
        }
        return new SnapshotInfo(t, pid, address, String.format("0x%016X", address), buf.length, sha);
    }

    public SnapshotDiffResult diffSnapshots(String tagA,
                                            String tagB,
                                            int maxDiffs,
                                            Integer oldValue,
                                            Integer newValue,
                                            int width) {
        if (tagA == null || tagA.isBlank()) throw new IllegalArgumentException("tagA is required");
        if (tagB == null || tagB.isBlank()) throw new IllegalArgumentException("tagB is required");
        if (maxDiffs <= 0) throw new IllegalArgumentException("maxDiffs must be > 0");
        if (width != 1 && width != 2 && width != 4) throw new IllegalArgumentException("width must be 1, 2, or 4");
        if ((oldValue == null) != (newValue == null)) {
            throw new IllegalArgumentException("oldValue and newValue must both be set or both be omitted");
        }

        Snapshot a = snapshots.get(tagA.trim());
        Snapshot b = snapshots.get(tagB.trim());
        if (a == null) throw new IllegalArgumentException("Unknown tagA: " + tagA);
        if (b == null) throw new IllegalArgumentException("Unknown tagB: " + tagB);
        if (a.pid != b.pid) {
            throw new IllegalArgumentException("Snapshots have different pid (" + a.pid + " vs " + b.pid + ")");
        }

        int n = Math.min(a.bytes.length, b.bytes.length);
        List<SnapshotDiffByte> diffs = new ArrayList<>();
        int diffCount = 0;
        for (int i = 0; i < n; i++) {
            int av = a.bytes[i] & 0xFF;
            int bv = b.bytes[i] & 0xFF;
            if (av == bv) continue;
            diffCount++;
            if (diffs.size() < maxDiffs) {
                diffs.add(new SnapshotDiffByte(i, av, bv));
            }
        }

        List<SnapshotTransitionHit> transitions = new ArrayList<>();
        if (oldValue != null) {
            long ov = Integer.toUnsignedLong(oldValue);
            long nv = Integer.toUnsignedLong(newValue);
            int step = 1;
            for (int i = 0; i + width <= n; i += step) {
                long av = readLeUnsigned(a.bytes, i, width);
                long bv = readLeUnsigned(b.bytes, i, width);
                if (av == ov && bv == nv) {
                    transitions.add(new SnapshotTransitionHit(i, width, av, bv));
                }
            }
        }

        return new SnapshotDiffResult(tagA.trim(), tagB.trim(), n, diffCount, diffs, transitions);
    }

    private long parseAddress(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("address is required");
        }
        String v = value.trim().toLowerCase(Locale.ROOT);
        try {
            if (v.startsWith("0x")) {
                return Long.parseUnsignedLong(v.substring(2), 16);
            }
            // allow decimal
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid address: " + value);
        }
    }

    private byte[] readMemoryBytes(int pid, long address, int size) {
        Path memPath = Path.of(PROC_ROOT, String.valueOf(pid), "mem");
        byte[] buf = new byte[size];
        int read;
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            memFile.seek(address);
            read = memFile.read(buf);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read " + memPath + " at " + String.format("0x%016X", address) + ": " + e.getMessage(), e);
        }
        if (read <= 0) return new byte[0];
        if (read < buf.length) return Arrays.copyOf(buf, read);
        return buf;
    }

    private String sha256Hex(byte[] bytes) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
        md.update(bytes);
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    private long readLeUnsigned(byte[] buf, int off, int width) {
        if (width == 1) return buf[off] & 0xFFL;
        if (width == 2) return ((buf[off] & 0xFFL)) | ((buf[off + 1] & 0xFFL) << 8);
        return ((buf[off] & 0xFFL))
                | ((buf[off + 1] & 0xFFL) << 8)
                | ((buf[off + 2] & 0xFFL) << 16)
                | ((buf[off + 3] & 0xFFL) << 24);
    }

    private String sanitizeTmpPath(String outPath) {
        if (outPath == null || outPath.isBlank()) {
            throw new IllegalArgumentException("outPath is required");
        }
        String p = outPath.trim();
        if (!p.startsWith("/tmp/")) {
            throw new IllegalArgumentException("outPath must start with /tmp/");
        }
        if (p.contains("..")) {
            throw new IllegalArgumentException("outPath must not contain '..'");
        }
        return p;
    }

    public RamScanResult scanForPlayerName(String processHint,
                                           String playerName,
                                           String encoding,
                                           int maxHits,
                                           long maxBytesPerRegion,
                                           boolean fullWordOnly,
                                           boolean anonymousWritableOnly,
                                           boolean scanPointers,
                                           long maxPointerScanBytesPerRegion,
                                           int maxPointerReferencesPerHit,
                                           boolean scanIds,
                                           long maxIdScanBytesPerRegion,
                                           int maxIdReferencesPerHit,
                                           Integer expectCrossing,
                                           Integer expectFinishing,
                                           Integer expectJumpingReach) {
        RunningProcess process = resolveProcess(processHint);
        return scanForPlayerName(
                process,
                playerName,
                encoding,
                maxHits,
                maxBytesPerRegion,
                fullWordOnly,
                anonymousWritableOnly,
                scanPointers,
                maxPointerScanBytesPerRegion,
                maxPointerReferencesPerHit,
                scanIds,
                maxIdScanBytesPerRegion,
                maxIdReferencesPerHit,
                new AttributeExpectations(expectCrossing, expectFinishing, expectJumpingReach)
        );
    }

    public RamScanResult scanForPlayerNameByPid(int pid,
                                                String playerName,
                                                String encoding,
                                                int maxHits,
                                                long maxBytesPerRegion,
                                                boolean fullWordOnly,
                                                boolean anonymousWritableOnly,
                                                boolean scanPointers,
                                                long maxPointerScanBytesPerRegion,
                                                int maxPointerReferencesPerHit,
                                                boolean scanIds,
                                                long maxIdScanBytesPerRegion,
                                                int maxIdReferencesPerHit,
                                                Integer expectCrossing,
                                                Integer expectFinishing,
                                                Integer expectJumpingReach) {
        RunningProcess process = describeProcess(pid);
        return scanForPlayerName(
                process,
                playerName,
                encoding,
                maxHits,
                maxBytesPerRegion,
                fullWordOnly,
                anonymousWritableOnly,
                scanPointers,
                maxPointerScanBytesPerRegion,
                maxPointerReferencesPerHit,
                scanIds,
                maxIdScanBytesPerRegion,
                maxIdReferencesPerHit,
                new AttributeExpectations(expectCrossing, expectFinishing, expectJumpingReach)
        );
    }

    private RamScanResult scanForPlayerName(RunningProcess process,
                                            String playerName,
                                            String encoding,
                                            int maxHits,
                                            long maxBytesPerRegion,
                                            boolean fullWordOnly,
                                            boolean anonymousWritableOnly,
                                            boolean scanPointers,
                                            long maxPointerScanBytesPerRegion,
                                            int maxPointerReferencesPerHit,
                                            boolean scanIds,
                                            long maxIdScanBytesPerRegion,
                                            int maxIdReferencesPerHit,
                                            AttributeExpectations attributeExpectations) {
        if (playerName == null || playerName.isBlank()) {
            throw new IllegalArgumentException("playerName cannot be empty");
        }

        List<MemoryRegion> regions = listMemoryRegions(process.pid());
        String enc = encoding == null ? "utf8" : encoding.trim().toLowerCase(Locale.ROOT);
        byte[] needle = switch (enc) {
            case "utf16le", "utf-16le", "utf16" -> playerName.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
            default -> playerName.getBytes(StandardCharsets.UTF_8);
        };
        boolean ignoreCase = !(enc.equals("utf16le") || enc.equals("utf-16le") || enc.equals("utf16"));
        boolean effectiveFullWordOnly = ignoreCase && fullWordOnly;

        List<PlayerMemoryHit> hits = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        int scannedRegions = 0;

        Path memPath = Path.of(PROC_ROOT, String.valueOf(process.pid()), "mem");
        try (RandomAccessFile memFile = new RandomAccessFile(memPath.toFile(), "r")) {
            for (MemoryRegion region : regions) {
                if (hits.size() >= maxHits) {
                    break;
                }
                if (!region.readable()) {
                    continue;
                }
                if (anonymousWritableOnly && !region.anonymousWritable()) {
                    continue;
                }

                scannedRegions++;
                scanRegion(memFile, region, needle, maxHits, maxBytesPerRegion, ignoreCase, effectiveFullWordOnly, hits, warnings);
            }

            if (scanPointers && !hits.isEmpty()) {
                hits = enrichHitsWithPointers(
                        memFile,
                        regions,
                        hits,
                        anonymousWritableOnly,
                        maxPointerScanBytesPerRegion,
                        maxPointerReferencesPerHit,
                        warnings
                );
            }
            if (scanIds && !hits.isEmpty()) {
                hits = enrichHitsWithIds(
                        memFile,
                        regions,
                        hits,
                        anonymousWritableOnly,
                        maxIdScanBytesPerRegion,
                        maxIdReferencesPerHit,
                        attributeExpectations,
                        warnings
                );
            }
        } catch (IOException e) {
            warnings.add("Could not open process memory file " + memPath + ": " + e.getMessage());
            warnings.add("Linux ptrace restrictions may block /proc/<pid>/mem. Try running this service as root or set /proc/sys/kernel/yama/ptrace_scope to 0.");
        }

        return new RamScanResult(
                process.pid(),
                process.name(),
                process.command(),
                playerName,
                scannedRegions,
                hits,
                warnings
        );
    }

    private List<PlayerMemoryHit> enrichHitsWithPointers(RandomAccessFile memFile,
                                                         List<MemoryRegion> regions,
                                                         List<PlayerMemoryHit> hits,
                                                         boolean anonymousWritableOnly,
                                                         long maxPointerScanBytesPerRegion,
                                                         int maxPointerReferencesPerHit,
                                                         List<String> warnings) {
        Map<Long, List<PlayerPointerReference>> referencesByHitAddress = new HashMap<>();
        for (PlayerMemoryHit hit : hits) {
            referencesByHitAddress.put(hit.address(), new ArrayList<>());
        }

        long minScanBytes = Math.max(maxPointerScanBytesPerRegion, 8L);
        for (MemoryRegion region : regions) {
            if (!region.readable()) {
                continue;
            }
            if (anonymousWritableOnly && !region.anonymousWritable()) {
                continue;
            }
            scanRegionForPointers(
                    memFile,
                    region,
                    minScanBytes,
                    referencesByHitAddress,
                    maxPointerReferencesPerHit,
                    warnings
            );
        }

        List<PlayerMemoryHit> enriched = new ArrayList<>(hits.size());
        for (PlayerMemoryHit hit : hits) {
            PlayerMemoryAnalysis previous = hit.analysis();
            List<PlayerPointerReference> refs = List.copyOf(referencesByHitAddress.getOrDefault(hit.address(), List.of()));
            PlayerMemoryAnalysis merged = new PlayerMemoryAnalysis(
                    previous.hitType(),
                    previous.nearbyStrings(),
                    previous.nearbyInt32Candidates(),
                    previous.nearbyAttributeBytes(),
                    refs,
                    previous.idReferences()
            );
            enriched.add(new PlayerMemoryHit(
                    hit.address(),
                    hit.addressHex(),
                    hit.region(),
                    hit.contextAscii(),
                    hit.contextHex(),
                    merged
            ));
        }
        return enriched;
    }

    private List<PlayerMemoryHit> enrichHitsWithIds(RandomAccessFile memFile,
                                                    List<MemoryRegion> regions,
                                                    List<PlayerMemoryHit> hits,
                                                    boolean anonymousWritableOnly,
                                                    long maxIdScanBytesPerRegion,
                                                    int maxIdReferencesPerHit,
                                                    AttributeExpectations attributeExpectations,
                                                    List<String> warnings) {
        // Map candidate id -> list of hit addresses that consider it relevant
        Map<Integer, List<Long>> hitAddressesById = new HashMap<>();
        Map<Long, List<PlayerIdReference>> idRefsByHitAddress = new HashMap<>();
        for (PlayerMemoryHit hit : hits) {
            idRefsByHitAddress.put(hit.address(), new ArrayList<>());
            for (int id : collectCandidateIds(hit.analysis())) {
                hitAddressesById.computeIfAbsent(id, ignored -> new ArrayList<>()).add(hit.address());
            }
        }
        if (hitAddressesById.isEmpty()) {
            return hits;
        }

        long minScanBytes = Math.max(maxIdScanBytesPerRegion, 4L);
        for (MemoryRegion region : regions) {
            if (!region.readable()) {
                continue;
            }
            if (anonymousWritableOnly && !region.anonymousWritable()) {
                continue;
            }
            scanRegionForIds(
                    memFile,
                    region,
                    minScanBytes,
                    hitAddressesById,
                    idRefsByHitAddress,
                    maxIdReferencesPerHit,
                    attributeExpectations,
                    warnings
            );
        }

        List<PlayerMemoryHit> enriched = new ArrayList<>(hits.size());
        for (PlayerMemoryHit hit : hits) {
            PlayerMemoryAnalysis previous = hit.analysis();
            List<PlayerIdReference> refs = List.copyOf(idRefsByHitAddress.getOrDefault(hit.address(), List.of()));
            PlayerMemoryAnalysis merged = new PlayerMemoryAnalysis(
                    previous.hitType(),
                    previous.nearbyStrings(),
                    previous.nearbyInt32Candidates(),
                    previous.nearbyAttributeBytes(),
                    previous.pointerReferences(),
                    refs
            );
            enriched.add(new PlayerMemoryHit(
                    hit.address(),
                    hit.addressHex(),
                    hit.region(),
                    hit.contextAscii(),
                    hit.contextHex(),
                    merged
            ));
        }
        return enriched;
    }

    private List<Integer> collectCandidateIds(PlayerMemoryAnalysis analysis) {
        // Try to avoid tiny constants from name-table metadata (1, 17, 26, etc.)
        LinkedHashSet<Integer> ids = new LinkedHashSet<>();
        for (int value : analysis.nearbyInt32Candidates()) {
            if (isPlausibleEntityId(value)) {
                ids.add(value);
            }
        }
        for (PlayerPointerReference ref : analysis.pointerReferences()) {
            for (int value : ref.nearbyInt32Candidates()) {
                if (isPlausibleEntityId(value)) {
                    ids.add(value);
                }
            }
        }
        return List.copyOf(ids);
    }

    private boolean isPlausibleEntityId(int value) {
        return value >= 10_000 && value <= 50_000_000;
    }

    private void scanRegionForIds(RandomAccessFile memFile,
                                  MemoryRegion region,
                                  long maxBytesPerRegion,
                                  Map<Integer, List<Long>> hitAddressesById,
                                  Map<Long, List<PlayerIdReference>> idRefsByHitAddress,
                                  int maxIdReferencesPerHit,
                                  AttributeExpectations attributeExpectations,
                                  List<String> warnings) {
        long regionSize = region.endAddress() - region.startAddress();
        long maxScan = Math.min(regionSize, maxBytesPerRegion);
        long offsetInRegion = 0;
        byte[] tail = new byte[0];

        while (offsetInRegion < maxScan && hasIdCapacity(idRefsByHitAddress, maxIdReferencesPerHit)) {
            int toRead = (int) Math.min(CHUNK_SIZE, maxScan - offsetInRegion);
            byte[] chunk = new byte[toRead];
            long absoluteStart = region.startAddress() + offsetInRegion;
            try {
                memFile.seek(absoluteStart);
                int bytesRead = memFile.read(chunk);
                if (bytesRead <= 0) {
                    break;
                }
                if (bytesRead < toRead) {
                    byte[] resized = new byte[bytesRead];
                    System.arraycopy(chunk, 0, resized, 0, bytesRead);
                    chunk = resized;
                }
            } catch (IOException e) {
                warnings.add("ID scan read failed at 0x" + Long.toHexString(absoluteStart) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            byte[] merged = concat(tail, chunk);
            long mergedStartAddress = absoluteStart - tail.length;
            // Scan on 4-byte alignment to keep it fast. If we miss too much, we can relax to step=1 later.
            for (int i = 0; i + 3 < merged.length; i += 4) {
                int id = readIntLittleEndian(merged, i);
                List<Long> hitAddresses = hitAddressesById.get(id);
                if (hitAddresses == null || hitAddresses.isEmpty()) {
                    continue;
                }

                long refAddress = mergedStartAddress + i;
                byte[] window = readWindow(memFile, refAddress - ANALYSIS_RADIUS, (ANALYSIS_RADIUS * 2) + 4, warnings);
                if (window.length == 0) {
                    continue;
                }

                AttributeRun best = bestAttributeRun(window);
                AttributeBlock36 bestBlock36 = bestAttributeBlock36(window, attributeExpectations);
                if (bestBlock36.score <= 0 && best.score <= 0) {
                    continue;
                }

                PlayerIdReference reference = new PlayerIdReference(
                        id,
                        refAddress,
                        String.format("0x%016X", refAddress),
                        region.shortLabel(),
                        best.score,
                        best.encoding,
                        best.min,
                        best.max,
                        best.uniqueCount,
                        bestBlock36.score,
                        bestBlock36.encoding,
                        bestBlock36.offset,
                        bestBlock36.values,
                        bestBlock36.attributes,
                        best.values,
                        extractNearbyInt32Candidates(window),
                        extractNearbyStrings(window)
                );
                for (long hitAddress : hitAddresses) {
                    List<PlayerIdReference> refs = idRefsByHitAddress.get(hitAddress);
                    if (refs == null) {
                        continue;
                    }
                    addTopIdReference(refs, reference, maxIdReferencesPerHit);
                }
            }

            int keepTail = 3;
            if (keepTail > 0) {
                int start = Math.max(0, merged.length - keepTail);
                tail = new byte[merged.length - start];
                System.arraycopy(merged, start, tail, 0, tail.length);
            }
            offsetInRegion += chunk.length;
        }
    }

    private boolean hasIdCapacity(Map<Long, List<PlayerIdReference>> idRefsByHitAddress, int maxIdReferencesPerHit) {
        for (List<PlayerIdReference> refs : idRefsByHitAddress.values()) {
            if (refs.size() < maxIdReferencesPerHit) {
                return true;
            }
        }
        return false;
    }

    private void addTopIdReference(List<PlayerIdReference> refs, PlayerIdReference candidate, int maxIdReferencesPerHit) {
        refs.add(candidate);
        refs.sort(Comparator.comparingInt(PlayerIdReference::attributeScore).reversed());
        if (refs.size() > maxIdReferencesPerHit) {
            refs.subList(maxIdReferencesPerHit, refs.size()).clear();
        }
    }

    private void scanRegionForPointers(RandomAccessFile memFile,
                                       MemoryRegion region,
                                       long maxBytesPerRegion,
                                       Map<Long, List<PlayerPointerReference>> referencesByHitAddress,
                                       int maxPointerReferencesPerHit,
                                       List<String> warnings) {
        long regionSize = region.endAddress() - region.startAddress();
        long maxScan = Math.min(regionSize, maxBytesPerRegion);
        long offsetInRegion = 0;
        byte[] tail = new byte[0];

        while (offsetInRegion < maxScan && hasPointerCapacity(referencesByHitAddress, maxPointerReferencesPerHit)) {
            int toRead = (int) Math.min(CHUNK_SIZE, maxScan - offsetInRegion);
            byte[] chunk = new byte[toRead];
            long absoluteStart = region.startAddress() + offsetInRegion;
            try {
                memFile.seek(absoluteStart);
                int bytesRead = memFile.read(chunk);
                if (bytesRead <= 0) {
                    break;
                }
                if (bytesRead < toRead) {
                    byte[] resized = new byte[bytesRead];
                    System.arraycopy(chunk, 0, resized, 0, bytesRead);
                    chunk = resized;
                }
            } catch (IOException e) {
                warnings.add("Pointer scan read failed at 0x" + Long.toHexString(absoluteStart) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            byte[] merged = concat(tail, chunk);
            long mergedStartAddress = absoluteStart - tail.length;
            for (int i = 0; i + 7 < merged.length; i++) {
                long value = readLongLittleEndian(merged, i);
                List<PlayerPointerReference> refs = referencesByHitAddress.get(value);
                if (refs == null || refs.size() >= maxPointerReferencesPerHit) {
                    continue;
                }
                byte[] pointerWindow = slice(merged, i - POINTER_ANALYSIS_RADIUS, i + 8 + POINTER_ANALYSIS_RADIUS);
                long refAddress = mergedStartAddress + i;
                refs.add(new PlayerPointerReference(
                        refAddress,
                        String.format("0x%016X", refAddress),
                        region.shortLabel(),
                        extractNearbyInt32Candidates(pointerWindow),
                        extractNearbyAttributeBytes(pointerWindow),
                        extractNearbyStrings(pointerWindow)
                ));
            }

            int keepTail = 7;
            if (keepTail > 0) {
                int start = Math.max(0, merged.length - keepTail);
                tail = new byte[merged.length - start];
                System.arraycopy(merged, start, tail, 0, tail.length);
            }
            offsetInRegion += chunk.length;
        }
    }

    private boolean hasPointerCapacity(Map<Long, List<PlayerPointerReference>> referencesByHitAddress, int maxPointerReferencesPerHit) {
        for (List<PlayerPointerReference> refs : referencesByHitAddress.values()) {
            if (refs.size() < maxPointerReferencesPerHit) {
                return true;
            }
        }
        return false;
    }

    private RunningProcess describeProcess(int pid) {
        Path pidPath = Path.of(PROC_ROOT, String.valueOf(pid));
        if (!Files.isDirectory(pidPath)) {
            throw new IllegalArgumentException("Process with pid " + pid + " does not exist");
        }
        String comm = readProcFile(pidPath.resolve("comm")).trim();
        String cmdline = readCmdline(pidPath.resolve("cmdline"));
        return new RunningProcess(pid, comm, cmdline);
    }

    private void scanRegion(RandomAccessFile memFile,
                            MemoryRegion region,
                            byte[] needle,
                            int maxHits,
                            long maxBytesPerRegion,
                            boolean ignoreCase,
                            boolean fullWordOnly,
                            List<PlayerMemoryHit> hits,
                            List<String> warnings) {
        long regionSize = region.endAddress() - region.startAddress();
        long maxScan = Math.min(regionSize, Math.max(maxBytesPerRegion, needle.length));
        long offsetInRegion = 0;
        byte[] tail = new byte[0];

        while (offsetInRegion < maxScan && hits.size() < maxHits) {
            int toRead = (int) Math.min(CHUNK_SIZE, maxScan - offsetInRegion);
            byte[] chunk = new byte[toRead];
            long absoluteStart = region.startAddress() + offsetInRegion;
            try {
                memFile.seek(absoluteStart);
                int bytesRead = memFile.read(chunk);
                if (bytesRead <= 0) {
                    break;
                }
                if (bytesRead < toRead) {
                    byte[] resized = new byte[bytesRead];
                    System.arraycopy(chunk, 0, resized, 0, bytesRead);
                    chunk = resized;
                }
            } catch (IOException e) {
                warnings.add("Read failed at 0x" + Long.toHexString(absoluteStart) + " in region " + region.shortLabel() + ": " + e.getMessage());
                break;
            }

            byte[] merged = concat(tail, chunk);
            int foundAt = 0;
            while (foundAt <= merged.length - needle.length && hits.size() < maxHits) {
                int idx = ignoreCase
                        ? indexOfIgnoreCase(merged, needle, foundAt, fullWordOnly)
                        : indexOfExact(merged, needle, foundAt);
                if (idx < 0) {
                    break;
                }
                long hitAddress = absoluteStart - tail.length + idx;
                PlayerMemoryAnalysis analysis = buildAnalysis(merged, idx, needle.length, region);
                hits.add(new PlayerMemoryHit(
                        hitAddress,
                        String.format("0x%016X", hitAddress),
                        region.shortLabel(),
                        asciiContext(merged, idx, needle.length, 48),
                        hexContext(merged, idx, needle.length, 32),
                        analysis
                ));
                foundAt = idx + 1;
            }

            int keepTail = Math.max(ANALYSIS_RADIUS, Math.max(needle.length - 1, 0));
            if (keepTail > 0) {
                int start = Math.max(0, merged.length - keepTail);
                tail = new byte[merged.length - start];
                System.arraycopy(merged, start, tail, 0, tail.length);
            }
            offsetInRegion += chunk.length;
        }
    }

    private Optional<MemoryRegion> parseRegion(String line) {
        if (line == null || line.isBlank()) {
            return Optional.empty();
        }
        String[] parts = line.trim().split("\\s+", 6);
        if (parts.length < 2) {
            return Optional.empty();
        }

        String[] addressParts = parts[0].split("-", 2);
        if (addressParts.length != 2) {
            return Optional.empty();
        }

        long start;
        long end;
        try {
            start = Long.parseUnsignedLong(addressParts[0], 16);
            end = Long.parseUnsignedLong(addressParts[1], 16);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }

        String perms = parts[1];
        String path = parts.length == 6 ? parts[5] : "";
        return Optional.of(new MemoryRegion(start, end, perms, path));
    }

    private int processScore(RunningProcess process, String hint) {
        int score = 0;
        String name = process.name() == null ? "" : process.name().toLowerCase(Locale.ROOT);
        String cmd = process.command() == null ? "" : process.command().toLowerCase(Locale.ROOT);
        String loweredHint = hint == null ? "" : hint.toLowerCase(Locale.ROOT);

        if (!loweredHint.isBlank()) {
            if (name.contains(loweredHint)) {
                score += 40;
            }
            if (cmd.contains(loweredHint)) {
                score += 30;
            }
        }
        if (cmd.contains("fm.exe")) {
            score += 80;
        }
        if (cmd.contains("football manager")) {
            score += 60;
        }
        if (name.contains("fm") || name.contains("wine") || name.contains("proton")) {
            score += 20;
        }
        if (WRAPPER_PROCESS_NAMES.contains(name)) {
            score -= 50;
        }
        if (!name.isBlank() && !WRAPPER_PROCESS_NAMES.contains(name)) {
            score += 10;
        }
        return score;
    }

    private boolean isNumeric(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private boolean isPidDirectory(Path path) {
        if (!Files.isDirectory(path)) {
            return false;
        }
        String name = path.getFileName().toString();
        for (int i = 0; i < name.length(); i++) {
            if (!Character.isDigit(name.charAt(i))) {
                return false;
            }
        }
        return !name.isEmpty();
    }

    private String readProcFile(Path file) {
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    private String readCmdline(Path cmdlinePath) {
        try {
            byte[] bytes = Files.readAllBytes(cmdlinePath);
            if (bytes.length == 0) {
                return "";
            }
            for (int i = 0; i < bytes.length; i++) {
                if (bytes[i] == 0) {
                    bytes[i] = ' ';
                }
            }
            return new String(bytes, StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            return "";
        }
    }

    private byte[] concat(byte[] left, byte[] right) {
        byte[] out = new byte[left.length + right.length];
        System.arraycopy(left, 0, out, 0, left.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }

    private int indexOfIgnoreCase(byte[] haystack, byte[] needle, int fromIndex, boolean fullWordOnly) {
        for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            if (matchesAtIgnoreCase(haystack, needle, i)
                    && (!fullWordOnly || hasWordBoundaries(haystack, i, needle.length))) {
                return i;
            }
        }
        return -1;
    }

    private int indexOfExact(byte[] haystack, byte[] needle, int fromIndex) {
        for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            boolean ok = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return i;
        }
        return -1;
    }

    private boolean matchesAtIgnoreCase(byte[] haystack, byte[] needle, int offset) {
        for (int j = 0; j < needle.length; j++) {
            if (toLowerAscii(haystack[offset + j]) != toLowerAscii(needle[j])) {
                return false;
            }
        }
        return true;
    }

    private boolean hasWordBoundaries(byte[] source, int start, int len) {
        int before = start - 1;
        int after = start + len;
        boolean leftOk = before < 0 || !isWordByte(source[before]);
        boolean rightOk = after >= source.length || !isWordByte(source[after]);
        return leftOk && rightOk;
    }

    private boolean isWordByte(byte b) {
        int v = b & 0xFF;
        return (v >= 'A' && v <= 'Z')
                || (v >= 'a' && v <= 'z')
                || (v >= '0' && v <= '9')
                || v == '_';
    }

    private PlayerMemoryAnalysis buildAnalysis(byte[] source, int hitIndex, int matchLen, MemoryRegion region) {
        int start = Math.max(0, hitIndex - ANALYSIS_RADIUS);
        int end = Math.min(source.length, hitIndex + matchLen + ANALYSIS_RADIUS);
        byte[] window = new byte[end - start];
        System.arraycopy(source, start, window, 0, window.length);
        List<String> nearbyStrings = extractNearbyStrings(window);
        List<Integer> nearbyInts = extractNearbyInt32Candidates(window);
        List<Integer> nearbyAttributes = extractNearbyAttributeBytes(window);
        return new PlayerMemoryAnalysis(
                detectHitType(region, nearbyStrings, nearbyAttributes),
                nearbyStrings,
                nearbyInts,
                nearbyAttributes,
                List.of(),
                List.of()
        );
    }

    private String detectHitType(MemoryRegion region, List<String> nearbyStrings, List<Integer> nearbyAttributes) {
        String regionPath = region.path() == null ? "" : region.path().toLowerCase(Locale.ROOT);
        if (regionPath.contains("global-metadata.dat")) {
            return "METADATA_TEXT";
        }

        int fullNameLike = 0;
        for (String value : nearbyStrings) {
            if (value.indexOf(' ') > 0 && startsWithUpper(value)) {
                fullNameLike++;
            }
        }
        if (fullNameLike >= 5) {
            return "PLAYER_NAME_TABLE";
        }
        if (nearbyAttributes.size() >= 8) {
            return "ATTRIBUTE_LIKE_BLOCK";
        }
        return "UNKNOWN";
    }

    private boolean startsWithUpper(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        char c = value.charAt(0);
        return c >= 'A' && c <= 'Z';
    }

    private List<String> extractNearbyStrings(byte[] window) {
        LinkedHashSet<String> strings = new LinkedHashSet<>();
        int i = 0;
        while (i < window.length && strings.size() < 12) {
            int start = i;
            while (i < window.length) {
                int b = window[i] & 0xFF;
                if (b < 32 || b > 126) {
                    break;
                }
                i++;
            }
            int len = i - start;
            if (len >= 4 && len <= 64) {
                String value = new String(window, start, len, StandardCharsets.UTF_8).trim();
                if (!value.isBlank()) {
                    strings.add(value);
                }
            }
            i++;
        }
        return List.copyOf(strings);
    }

    private List<Integer> extractNearbyInt32Candidates(byte[] window) {
        List<Integer> values = new ArrayList<>();
        for (int i = 0; i + 3 < window.length && values.size() < 16; i += 4) {
            int value = (window[i] & 0xFF)
                    | ((window[i + 1] & 0xFF) << 8)
                    | ((window[i + 2] & 0xFF) << 16)
                    | ((window[i + 3] & 0xFF) << 24);
            if (value > 0 && value < 50_000_000) {
                values.add(value);
            }
        }
        return values;
    }

    private List<Integer> extractNearbyAttributeBytes(byte[] window) {
        List<Integer> best = new ArrayList<>();
        List<Integer> current = new ArrayList<>();
        for (byte b : window) {
            int value = b & 0xFF;
            if (value >= 1 && value <= 20) {
                current.add(value);
                if (current.size() > best.size()) {
                    best = new ArrayList<>(current);
                }
            } else {
                current.clear();
            }
        }
        if (best.size() > 80) {
            return best.subList(0, 80);
        }
        return best;
    }

    private AttributeRun bestAttributeRun(byte[] window) {
        AttributeRun best = AttributeRun.empty();
        AttributeRun a = scoreRun("byte", extractBestRunByte(window));
        if (a.score > best.score) best = a;
        AttributeRun b = scoreRun("byte_stride2", extractBestRunByteStride2(window));
        if (b.score > best.score) best = b;
        AttributeRun c = scoreRun("u16_le", extractBestRunU16(window));
        if (c.score > best.score) best = c;
        return best;
    }

    private AttributeBlock36 bestAttributeBlock36(byte[] window, AttributeExpectations expectations) {
        AttributeBlock36 best = AttributeBlock36.empty();
        AttributeBlock36 a = scanAttributeBlock36Byte(window, expectations);
        if (a.score > best.score) best = a;
        AttributeBlock36 b = scanAttributeBlock36ByteStride2(window, expectations);
        if (b.score > best.score) best = b;
        AttributeBlock36 c = scanAttributeBlock36U16(window, expectations);
        if (c.score > best.score) best = c;
        return best;
    }

    private AttributeBlock36 scanAttributeBlock36Byte(byte[] window, AttributeExpectations expectations) {
        AttributeBlock36 best = AttributeBlock36.empty();
        for (int start = 0; start + 36 <= window.length; start++) {
            List<Integer> values = new ArrayList<>(36);
            int inRange = 0;
            for (int j = 0; j < 36; j++) {
                int v = window[start + j] & 0xFF;
                if (v >= 1 && v <= 20) {
                    inRange++;
                    values.add(v);
                } else {
                    values.add(0);
                }
            }
            if (inRange < 24) continue;
            AttributeBlock36 scored = scoreBlock36("byte", start, values, expectations);
            if (scored.score > best.score) best = scored;
        }
        return best;
    }

    private AttributeBlock36 scanAttributeBlock36ByteStride2(byte[] window, AttributeExpectations expectations) {
        AttributeBlock36 best = AttributeBlock36.empty();
        for (int parity = 0; parity < 2; parity++) {
            for (int start = parity; start + (36 * 2) <= window.length; start += 2) {
                List<Integer> values = new ArrayList<>(36);
                int inRange = 0;
                for (int j = 0; j < 36; j++) {
                    int v = window[start + (j * 2)] & 0xFF;
                    if (v >= 1 && v <= 20) {
                        inRange++;
                        values.add(v);
                    } else {
                        values.add(0);
                    }
                }
                if (inRange < 24) continue;
                AttributeBlock36 scored = scoreBlock36("byte_stride2", start, values, expectations);
                if (scored.score > best.score) best = scored;
            }
        }
        return best;
    }

    private AttributeBlock36 scanAttributeBlock36U16(byte[] window, AttributeExpectations expectations) {
        AttributeBlock36 best = AttributeBlock36.empty();
        for (int start = 0; start + (36 * 2) <= window.length; start += 2) {
            List<Integer> values = new ArrayList<>(36);
            int inRange = 0;
            for (int j = 0; j < 36; j++) {
                int off = start + (j * 2);
                int v = (window[off] & 0xFF) | ((window[off + 1] & 0xFF) << 8);
                if (v >= 1 && v <= 20) {
                    inRange++;
                    values.add(v);
                } else {
                    values.add(0);
                }
            }
            if (inRange < 24) continue;
            AttributeBlock36 scored = scoreBlock36("u16_le", start, values, expectations);
            if (scored.score > best.score) best = scored;
        }
        return best;
    }

    private AttributeBlock36 scoreBlock36(String encoding, int offset, List<Integer> values, AttributeExpectations expectations) {
        int min = 21, max = 0, sum = 0;
        int[] freq = new int[21];
        int unique = 0;
        int valid = 0;
        for (int v : values) {
            if (v >= 1 && v <= 20) {
                valid++;
                freq[v]++;
                if (freq[v] == 1) unique++;
                if (v < min) min = v;
                if (v > max) max = v;
                sum += v;
            }
        }
        if (valid < 24) {
            return AttributeBlock36.empty();
        }

        int score = 0;
        score += valid * 12;
        score += unique * 8;
        if (min <= 3) score += 80;
        if (max >= 18) score += 80;
        if (unique >= 12) score += 50;
        int meanTimes10 = (sum * 10) / Math.max(valid, 1);
        if (meanTimes10 >= 90 && meanTimes10 <= 150) score += 20;

        // Penalize blocks dominated by a single value (common false positive)
        int maxFreq = 0;
        for (int i = 1; i <= 20; i++) maxFreq = Math.max(maxFreq, freq[i]);
        if (maxFreq >= 12) score -= 120;

        // Penalize overly sequential patterns (e.g. 1,1,1,2,1,2,1,3...)
        int increasingSteps = 0;
        for (int i = 1; i < values.size(); i++) {
            int a = values.get(i - 1);
            int b = values.get(i);
            if (a >= 1 && a <= 20 && b >= 1 && b <= 20 && b == a + 1) increasingSteps++;
        }
        if (increasingSteps >= 10) score -= 150;

        Map<String, Integer> attrMap = toOutfieldAttributeMap(values);

        // If the user edited specific attributes, boost blocks that match those exact values
        if (expectations != null) {
            Integer expectCrossing = expectations.expectCrossing;
            Integer expectFinishing = expectations.expectFinishing;
            Integer expectJumpingReach = expectations.expectJumpingReach;
            if (expectCrossing != null && expectCrossing.equals(attrMap.get("crossing"))) score += 200;
            if (expectFinishing != null && expectFinishing.equals(attrMap.get("finishing"))) score += 200;
            if (expectJumpingReach != null && expectJumpingReach.equals(attrMap.get("jumpingReach"))) score += 250;
        }
        return new AttributeBlock36(encoding, offset, score, List.copyOf(values), attrMap);
    }

    private Map<String, Integer> toOutfieldAttributeMap(List<Integer> values36) {
        LinkedHashMap<String, Integer> map = new LinkedHashMap<>();
        int n = Math.min(OUTFIELD_ATTR_ORDER_36.size(), values36.size());
        for (int i = 0; i < n; i++) {
            int v = values36.get(i);
            if (v >= 1 && v <= 20) {
                map.put(OUTFIELD_ATTR_ORDER_36.get(i), v);
            }
        }
        return map;
    }

    private record AttributeBlock36(
            String encoding,
            int offset,
            int score,
            List<Integer> values,
            Map<String, Integer> attributes
    ) {
        static AttributeBlock36 empty() {
            return new AttributeBlock36("none", -1, 0, List.of(), Map.of());
        }
    }

    private record AttributeExpectations(
            Integer expectCrossing,
            Integer expectFinishing,
            Integer expectJumpingReach
    ) {
    }

    private List<Integer> extractBestRunByte(byte[] window) {
        List<Integer> best = new ArrayList<>();
        List<Integer> current = new ArrayList<>();
        for (byte b : window) {
            int value = b & 0xFF;
            if (value >= 1 && value <= 20) {
                current.add(value);
                if (current.size() > best.size()) {
                    best = new ArrayList<>(current);
                }
            } else {
                current.clear();
            }
        }
        return best;
    }

    private List<Integer> extractBestRunByteStride2(byte[] window) {
        List<Integer> best = new ArrayList<>();
        for (int parity = 0; parity < 2; parity++) {
            List<Integer> current = new ArrayList<>();
            for (int i = parity; i < window.length; i += 2) {
                int value = window[i] & 0xFF;
                if (value >= 1 && value <= 20) {
                    current.add(value);
                    if (current.size() > best.size()) {
                        best = new ArrayList<>(current);
                    }
                } else {
                    current.clear();
                }
            }
        }
        return best;
    }

    private List<Integer> extractBestRunU16(byte[] window) {
        List<Integer> best = new ArrayList<>();
        List<Integer> current = new ArrayList<>();
        for (int i = 0; i + 1 < window.length; i += 2) {
            int value = (window[i] & 0xFF) | ((window[i + 1] & 0xFF) << 8);
            if (value >= 1 && value <= 20) {
                current.add(value);
                if (current.size() > best.size()) {
                    best = new ArrayList<>(current);
                }
            } else {
                current.clear();
            }
        }
        return best;
    }

    private AttributeRun scoreRun(String encoding, List<Integer> values) {
        if (values == null || values.isEmpty()) {
            return AttributeRun.empty();
        }

        int len = Math.min(values.size(), 80);
        List<Integer> clipped = values.subList(0, len);
        int min = 21;
        int max = 0;
        boolean[] seen = new boolean[21];
        int unique = 0;
        int sum = 0;
        for (int v : clipped) {
            sum += v;
            if (v < min) min = v;
            if (v > max) max = v;
            if (!seen[v]) {
                seen[v] = true;
                unique++;
            }
        }

        // Heuristic: real FM attribute blocks usually contain some low and some high values,
        // not a flat 8-12 blob.
        int score = len * 10;
        score += unique * 5;
        if (min <= 3) score += 40;
        if (max >= 17) score += 40;
        if (unique >= 10) score += 20;
        int meanTimes10 = (sum * 10) / len;
        if (meanTimes10 >= 90 && meanTimes10 <= 150) score += 10; // mean in ~9-15 range

        // Penalize low-variance runs.
        if ((max - min) <= 4) score -= 60;

        return new AttributeRun(encoding, score, min, max, unique, List.copyOf(clipped));
    }

    private record AttributeRun(
            String encoding,
            int score,
            int min,
            int max,
            int uniqueCount,
            List<Integer> values
    ) {
        static AttributeRun empty() {
            return new AttributeRun("none", 0, 0, 0, 0, List.of());
        }
    }

    private int readIntLittleEndian(byte[] source, int offset) {
        return (source[offset] & 0xFF)
                | ((source[offset + 1] & 0xFF) << 8)
                | ((source[offset + 2] & 0xFF) << 16)
                | ((source[offset + 3] & 0xFF) << 24);
    }

    private long readLongLittleEndian(byte[] source, int offset) {
        return (source[offset] & 0xFFL)
                | ((source[offset + 1] & 0xFFL) << 8)
                | ((source[offset + 2] & 0xFFL) << 16)
                | ((source[offset + 3] & 0xFFL) << 24)
                | ((source[offset + 4] & 0xFFL) << 32)
                | ((source[offset + 5] & 0xFFL) << 40)
                | ((source[offset + 6] & 0xFFL) << 48)
                | ((source[offset + 7] & 0xFFL) << 56);
    }

    private byte[] slice(byte[] source, int startInclusive, int endExclusive) {
        int start = Math.max(0, startInclusive);
        int end = Math.min(source.length, endExclusive);
        if (end <= start) {
            return new byte[0];
        }
        byte[] out = new byte[end - start];
        System.arraycopy(source, start, out, 0, out.length);
        return out;
    }

    private byte[] readWindow(RandomAccessFile memFile, long startAddress, int size, List<String> warnings) {
        if (size <= 0) {
            return new byte[0];
        }
        long start = Math.max(0, startAddress);
        byte[] buf = new byte[size];
        try {
            memFile.seek(start);
            int read = memFile.read(buf);
            if (read <= 0) {
                return new byte[0];
            }
            if (read == size) {
                return buf;
            }
            byte[] resized = new byte[read];
            System.arraycopy(buf, 0, resized, 0, read);
            return resized;
        } catch (IOException e) {
            warnings.add("Window read failed at 0x" + Long.toHexString(start) + ": " + e.getMessage());
            return new byte[0];
        }
    }

    private byte toLowerAscii(byte value) {
        if (value >= 'A' && value <= 'Z') {
            return (byte) (value + 32);
        }
        return value;
    }

    private String asciiContext(byte[] source, int hitIndex, int matchLen, int radius) {
        int start = Math.max(0, hitIndex - radius);
        int end = Math.min(source.length, hitIndex + matchLen + radius);
        StringBuilder sb = new StringBuilder(end - start);
        for (int i = start; i < end; i++) {
            int b = source[i] & 0xFF;
            if (b >= 32 && b <= 126) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    private String hexContext(byte[] source, int hitIndex, int matchLen, int radius) {
        int start = Math.max(0, hitIndex - radius);
        int end = Math.min(source.length, hitIndex + matchLen + radius);
        StringBuilder sb = new StringBuilder((end - start) * 3);
        for (int i = start; i < end; i++) {
            sb.append(String.format("%02X", source[i] & 0xFF));
            if (i < end - 1) {
                sb.append(' ');
            }
        }
        return sb.toString();
    }
}
