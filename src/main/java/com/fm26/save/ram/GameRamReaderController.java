package com.fm26.save.ram;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Arrays;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/ram")
public class GameRamReaderController {

    private final GameRamReaderService gameRamReaderService;

    public GameRamReaderController(GameRamReaderService gameRamReaderService) {
        this.gameRamReaderService = gameRamReaderService;
    }

    @GetMapping("/processes")
    public List<RunningProcess> processes(@RequestParam(required = false) String name) {
        return gameRamReaderService.listProcesses(name);
    }

    @GetMapping("/processes/{pid}/regions")
    public List<MemoryRegion> memoryRegions(@PathVariable int pid) {
        return gameRamReaderService.listMemoryRegions(pid);
    }

    @GetMapping("/dump")
    public MemoryDump dump(
            @RequestParam int pid,
            @RequestParam String address,
            @RequestParam(defaultValue = "4096") int size
    ) {
        return gameRamReaderService.dumpMemory(pid, address, size);
    }

    @GetMapping("/dump-file")
    public MemoryDumpFile dumpFile(
            @RequestParam int pid,
            @RequestParam String address,
            @RequestParam(defaultValue = "65536") int size,
            @RequestParam String out
    ) {
        return gameRamReaderService.dumpMemoryToFile(pid, address, size, out);
    }

    @GetMapping("/scan-pattern")
    public PatternScanResult scanPattern(
            @RequestParam int pid,
            @RequestParam String pattern,
            @RequestParam(defaultValue = "28") int baseIndex,
            @RequestParam(defaultValue = "10") int maxHits,
            @RequestParam(defaultValue = "true") boolean anonymousWritableOnly,
            @RequestParam(defaultValue = "33554432") long maxBytesPerRegion,
            @RequestParam(defaultValue = "false") boolean unordered,
            @RequestParam(defaultValue = "50") int maxRegions,
            @RequestParam(required = false) String regionStart,
            @RequestParam(required = false) String regionEnd,
            @RequestParam(defaultValue = "all") String encodings
    ) {
        List<Integer> values = Arrays.stream(pattern.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .map(Integer::parseInt)
                .collect(Collectors.toList());
        return gameRamReaderService.scanForPatternByPid(pid, values, baseIndex, maxHits, anonymousWritableOnly, maxBytesPerRegion, unordered, maxRegions, regionStart, regionEnd, encodings);
    }

    @GetMapping("/scan-bag")
    public BagScanResult scanBag(
            @RequestParam int pid,
            @RequestParam String bag,
            @RequestParam(defaultValue = "1024") int windowBytes,
            @RequestParam(defaultValue = "64") int stepBytes,
            @RequestParam(defaultValue = "20") int maxHits,
            @RequestParam(defaultValue = "true") boolean anonymousWritableOnly,
            @RequestParam(defaultValue = "true") boolean noExecOnly,
            @RequestParam(defaultValue = "50") int maxRegions,
            @RequestParam(defaultValue = "67108864") long maxBytesPerRegion,
            @RequestParam(required = false) String regionStart,
            @RequestParam(required = false) String regionEnd
    ) {
        List<Integer> values = Arrays.stream(bag.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .map(Integer::parseInt)
                .collect(Collectors.toList());
        return gameRamReaderService.scanForBagByPid(pid, values, windowBytes, stepBytes, maxHits, anonymousWritableOnly, noExecOnly, maxRegions, maxBytesPerRegion, regionStart, regionEnd);
    }

    @GetMapping("/scan-int")
    public IntScanResult scanInt(
            @RequestParam int pid,
            @RequestParam int value,
            @RequestParam(defaultValue = "100") int maxHits,
            @RequestParam(defaultValue = "33554432") long maxBytesPerRegion,
            @RequestParam(defaultValue = "false") boolean anonymousWritableOnly,
            @RequestParam(defaultValue = "true") boolean noExecOnly,
            @RequestParam(defaultValue = "true") boolean scanPointers,
            @RequestParam(defaultValue = "33554432") long maxPointerScanBytesPerRegion,
            @RequestParam(defaultValue = "12") int maxPointerReferencesPerHit,
            @RequestParam(required = false) String regionStart,
            @RequestParam(required = false) String regionEnd
    ) {
        return gameRamReaderService.scanForInt32ByPid(pid, value, maxHits, maxBytesPerRegion, anonymousWritableOnly, noExecOnly, scanPointers, maxPointerScanBytesPerRegion, maxPointerReferencesPerHit, regionStart, regionEnd);
    }

    @GetMapping("/scan-pointers-to")
    public PointerScanResult scanPointersTo(
            @RequestParam int pid,
            @RequestParam String target,
            @RequestParam(defaultValue = "200") int maxReferences,
            @RequestParam(defaultValue = "33554432") long maxBytesPerRegion,
            @RequestParam(defaultValue = "false") boolean anonymousWritableOnly,
            @RequestParam(defaultValue = "true") boolean noExecOnly
    ) {
        return gameRamReaderService.scanPointersTo(pid, target, maxReferences, maxBytesPerRegion, anonymousWritableOnly, noExecOnly);
    }

    @GetMapping("/scan-lvtp")
    public LvtpRunScanResult scanLvtpRuns(
            @RequestParam int pid,
            @RequestParam(defaultValue = "5") int maxRuns,
            @RequestParam(defaultValue = "40") int minRunRecords,
            @RequestParam(defaultValue = "false") boolean anonymousWritableOnly,
            @RequestParam(defaultValue = "true") boolean noExecOnly,
            @RequestParam(defaultValue = "50") int maxRegions,
            @RequestParam(defaultValue = "33554432") long maxBytesPerRegion,
            @RequestParam(required = false) String regionStart,
            @RequestParam(required = false) String regionEnd
    ) {
        return gameRamReaderService.scanForLvtpRuns(pid, maxRuns, minRunRecords, anonymousWritableOnly, noExecOnly, maxRegions, maxBytesPerRegion, regionStart, regionEnd);
    }

    @GetMapping("/attributes-lvtp")
    public LvtpAttributesResult attributesFromBestLvtpRun(
            @RequestParam int pid,
            @RequestParam(defaultValue = "true") boolean anonymousWritableOnly,
            @RequestParam(defaultValue = "true") boolean noExecOnly,
            @RequestParam(defaultValue = "200") int maxRegions,
            @RequestParam(defaultValue = "33554432") long maxBytesPerRegion,
            @RequestParam(defaultValue = "40") int minRunRecords,
            @RequestParam(required = false) String regionStart,
            @RequestParam(required = false) String regionEnd
    ) {
        return gameRamReaderService.attributesFromBestLvtpRun(pid, anonymousWritableOnly, noExecOnly, maxRegions, maxBytesPerRegion, minRunRecords, regionStart, regionEnd);
    }

    @GetMapping("/scan")
    public RamScanResult scanPlayer(
            @RequestParam(required = false) Integer pid,
            @RequestParam(defaultValue = "football") String process,
            @RequestParam String player,
            @RequestParam(defaultValue = "utf8") String encoding,
            @RequestParam(defaultValue = "20") int maxHits,
            @RequestParam(defaultValue = "33554432") long maxBytesPerRegion,
            @RequestParam(defaultValue = "true") boolean fullWordOnly,
            @RequestParam(defaultValue = "true") boolean anonymousWritableOnly,
            @RequestParam(defaultValue = "true") boolean scanPointers,
            @RequestParam(defaultValue = "12582912") long maxPointerScanBytesPerRegion,
            @RequestParam(defaultValue = "12") int maxPointerReferencesPerHit,
            @RequestParam(defaultValue = "true") boolean scanIds,
            @RequestParam(defaultValue = "16777216") long maxIdScanBytesPerRegion,
            @RequestParam(defaultValue = "24") int maxIdReferencesPerHit,
            @RequestParam(required = false) Integer expectCrossing,
            @RequestParam(required = false) Integer expectFinishing,
            @RequestParam(required = false) Integer expectJumpingReach
    ) {
        if (pid != null) {
            return gameRamReaderService.scanForPlayerNameByPid(
                    pid,
                    player,
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
                    expectCrossing,
                    expectFinishing,
                    expectJumpingReach
            );
        }
        return gameRamReaderService.scanForPlayerName(
                process,
                player,
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
                expectCrossing,
                expectFinishing,
                expectJumpingReach
        );
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, String>> handleStateError(IllegalStateException ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", ex.getMessage()));
    }
}
