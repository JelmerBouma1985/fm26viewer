# FM26 Save Game Reader

Spring Boot 3.5 + JDK 25 project that extracts data from Football Manager 26 save files (`.fm`) into an embedded H2 database.

Current state:
- Decompresses **all zstd frames** inside the FMF container and picks the largest as the primary dataset.
- Detects TAD sections (`tad..`).
- Scans for length-prefixed strings and stores them in H2.
- Scans for raw ASCII strings (non length-prefixed) and stores them in H2.
- Extracts **players** using a name heuristic (placeholder until full schema is reversed).
- Optionally captures debug hex around a specific player name to help reverse record structure.

## Configure
Edit `src/main/resources/application.yml`:
- `fm26.save-path`: path to `.fm` save
- `fm26.db-path`: path to H2 database file
- `fm26.max-string-len`: max string length for scanning
- `fm26.attribute-window-before`: bytes before ID hit to include in attribute window
- `fm26.attribute-window-after`: bytes after ID hit to include in attribute window
- `fm26.attribute-pair-id-min`: minimum attribute id for value/id pair extraction
- `fm26.attribute-pair-id-max`: maximum attribute id for value/id pair extraction
- `fm26.attribute-debug-window-start`: debug window start offset (global)
- `fm26.attribute-debug-window-end`: debug window end offset (global)
- `fm26.attribute-debug-dump-dir`: output dir for debug window dump
- `fm26.frame-index`: force parsing a specific zstd frame (default -1 = largest frame)
- `fm26.global-run-scan-enabled`: enable global 36-value run scan (0..20) across decompressed data
- `fm26.global-run-limit`: max number of global runs to store
- `fm26.debug-run-scan-enabled`: enable transformed run scan within debug window
- `fm26.debug-run-limit`: max number of debug runs to store
- `fm26.debug-align-window`: number of bytes after the name to scan for alignment
- `fm26.debug-align-allow-zero`: include zero values when aligning
- `fm26.debug-pointer-min`: minimum int32 value to treat as a pointer candidate
- `fm26.debug-pointer-limit`: maximum pointer candidates to store

## Run
```
./mvnw -q -DskipTests spring-boot:run
```
Or pass args (override config):
```
./mvnw -q -DskipTests spring-boot:run \
  -Dspring-boot.run.arguments="/path/Unemployed.fm,/tmp/fm26-save.h2,200"
```

## Output tables
- `meta` (save path, decompressed size, timestamp)
- `save_frames` (zstd frame offsets, compressed/decompressed sizes, success/error)
- `frame_debug_hits` (name hits per frame to locate the right payload)
- `sections` (TAD section offsets)
- `strings` (offset, length, value, section)
- `raw_strings` (raw offset, value, section)
- `players` (heuristic player names)
- `player_debug` (hex + base64 window around a configured name)
- `player_index` (derived ids + DOB from name record)
- `player_attributes` (mapped attribute values for known field IDs)
- `attribute_candidates` (top candidate windows around person/player id hits)
- `attribute_sequences` (top 3 contiguous 1..20 sequences per candidate)
- `attribute_value_streams` (ordered stream of 1..20 values per candidate window)
- `attribute_pairs` (value/id pairs within candidate windows, both directions)
- `attribute_runs` (top contiguous 36-value runs of 1..20 per candidate)
- `attribute_window_clusters` (best 36-value cluster per candidate window)
- `attribute_window_matches` (best 36-value contiguous match per candidate with small value shift)
- `attribute_run_strides` (top 36-value runs using stride=2 per candidate)
- `attribute_debug_ints` (int32 values from the configured debug window)
- `attribute_global_runs` (best 36-value runs across decompressed data)
- `attribute_global_hist_runs` (best 36-value runs by histogram similarity)
- `attribute_debug_runs` (best transformed runs within debug window)
- `attribute_debug_runs16` (best 16-bit runs within debug window)
- `attribute_debug_alignments` (best alignment of 1..20 values after name in debug window)
- `attribute_debug_pointers` (int32 pointer candidates with hex sample and 1..20 byte score)
- `attribute_debug_fields` (records matching ? 4F 00 FF pattern with tag/field id + candidate values)
- `attribute_debug_tags` (records matching ? ? 00 FF pattern with tag/marker)
- `attribute_name_refs` (occurrences of attribute names with nearby id candidates)
- `attribute_match_scores` (best alignment cost vs Quinten's known attributes using multiple filters)
- `attribute_match_deltas` (per-attribute delta between target and best match)

## Next steps
- Reverse TAD record structures to map real player records (ids, attributes, club ids, etc.).
- Replace heuristic with proper entity parsing into a `players` table.

## RAM reader service (live process)
This project now also includes a Linux `/proc` RAM reader for a running game process.

Endpoints:
- `GET /api/ram/processes?name=football` -> list matching processes (`pid`, name, full command)
- `GET /api/ram/processes/{pid}/regions` -> list memory maps from `/proc/{pid}/maps`
- `GET /api/ram/scan?process=football&player=Justin&maxHits=20&maxBytesPerRegion=33554432&fullWordOnly=true&anonymousWritableOnly=true&scanPointers=true&scanIds=true` -> auto-select a likely process and scan readable memory
- `GET /api/ram/scan?pid=12345&player=Justin` -> scan a specific process id directly

Notes:
- Reading `/proc/{pid}/mem` depends on Linux ptrace/security settings and user permissions.
- If your user cannot read the target process memory directly, run with elevated permissions.
- For better player hits, use full names (example: `player=Quinten%20Ryan%20Crispito%20Timber`) and keep `fullWordOnly=true`.
- Each hit now includes `analysis.hitType` (`PLAYER_NAME_TABLE`, `ATTRIBUTE_LIKE_BLOCK`, `METADATA_TEXT`, `UNKNOWN`) and `analysis.pointerReferences` to locations that hold pointers to the name string.
- If you get name-table hits (lots of nearby names), check `analysis.idReferences` for candidate locations where the player's entity id appears near attribute-like value runs (1..20).
