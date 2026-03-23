# FM26 Save Reverse Engineering Context

This file is the project-local memory for how the current extractor was reverse engineered.

It exists so future work can resume quickly without reconstructing months of trial-and-error from chat history.

## Scope

This document covers:

- generic player discovery
- generic visible attribute decoding
- generic current ability / potential ability decoding
- generic name resolution
- where the implementation currently lives
- what was proven by save diffs versus what is still only heuristic

It does not try to re-document every experimental probe class in detail. It focuses on the rules that actually survived into the main extractor.

## Current Main Files

- [GenericPlayerSubsetExtractor.java](src/main/java/com/fm26/save/analysis/GenericPlayerSubsetExtractor.java)
- [StandardVisibleBlockProbe.java](src/main/java/com/fm26/save/analysis/StandardVisibleBlockProbe.java)
- [NameResolverDebugProbe.java](src/main/java/com/fm26/save/analysis/NameResolverDebugProbe.java)
- [AllPlayersExtractor.java](src/main/java/com/fm26/save/analysis/AllPlayersExtractor.java)
- [TraunerFullProfileJsonExporter.java](src/main/java/com/fm26/save/analysis/TraunerFullProfileJsonExporter.java)

The current live output that was used as source of truth during validation is typically:

- `/tmp/generic_subset_players.json`

## Base Save And Methodology

The entire reverse-engineering process relied on controlled one-field edits from the same base save:

- `games/Feyenoord_after.fm`

Rules that mattered:

- only one edited field per save whenever possible
- no time advance
- no unrelated edits
- use large distinctive changes:
  - visible attributes mostly to `20` or `1`
  - CA to `1`
  - PA to `200`
  - names to `Zqx`

This gave deterministic diffs and made byte-level mapping possible.

## High-Level Data Model That Emerged

The save is not a single flat player record.

It contains at least:

- a low-offset duplicated `person` anchor
- one or more player-only index/object references
- local payload blocks near the person anchor
- string tables for first names, surnames, and common names

The project originally started by hard-mapping Trauner. The generic extractor came later once we realized most players share a standard visible-attribute block, while names are resolved through one or more local name-reference shapes.

## Player Discovery

### What survived

The extractor does **not** rely on simple raw ID occurrence counts anymore.

Important lessons learned:

- raw `u32` hit counts produced false positives, especially for small IDs
- some real players do not fit naive `5 hits = player` rules
- some non-players can accidentally look player-like if only low-level duplicated values are counted

### Discovery approach that proved useful

The surviving approach is a combination of:

- duplicated low-offset `person` pair detection
- local typed-object/preamble validation
- later cleanup using decoded payload quality
- final cleanup using CA/PA presence

One important cleanup rule that stayed:

- if a candidate has neither `current_ability` nor `potential_ability`, reject it as a player

That rule removed a set of late false positives cleanly.

## Generic Visible Attribute Decoder

This was the big breakthrough.

### What was learned

At first it looked like there were many player-specific profile families:

- Trauner
- Smal
- Kooistra
- Aidoo
- Toure
- Rômulo
- several forward-local variants

That was partly true for local placement, but it was misleading for visible attributes.

The generic breakthrough was:

- there is one dominant standard visible block
- the field order is shared broadly across players
- what changes is mainly:
  - block start relative to `personPair`
  - a small decode bias
  - occasionally a low-anchor variant for special low-ID cases

### Standard visible block shape

The standard visible block is a local block near `personPair`.

Its core properties:

- main block length is effectively `52` bytes for visible/profile values
- `crossing` and `dribbling` live in the 2-byte prefix immediately before the main block
- most visible attributes are stored as one byte representing roughly `value * 5`, with a small per-block bias

### Generic visible field order

The generic decoder uses one shared field order.

In `GenericPlayerSubsetExtractor.java`, the standard visible mapping is represented by offsets relative to `standardStart`.

Important examples:

- `crossing -> -2`
- `dribbling -> -1`
- `finishing -> 0`
- `heading -> 1`
- `long_shots -> 2`
- `marking -> 3`
- `off_the_ball -> 4`
- `passing -> 5`
- `penalty_taking -> 6`
- `tackling -> 7`
- `vision -> 8`
- ...

This standard mapping ended up validating against a large screenshot sanity set and many one-field save edits.

### Bias-based decode rule

The final visible decode is not simply `stored / 5`.

The generic rule that survived:

- each local visible block has a small per-block bias
- decode is:
  - `stored == 0 -> 0`
  - otherwise `max(1, floor((stored + bias) / 5))`

That low-end clamp was important.

It was proven by player `2000022822`, where:

- raw `penalty_taking` was `1`
- visible value in FM was `1`

Without the clamp, some non-zero stored values incorrectly decoded to `0`.

### Bias values

Observed bias values during reverse engineering included:

- `0`
- `1`
- `2`
- `3`
- `4`

Examples:

- Gündoğan needed a non-zero bias
- Walden needed a different non-zero bias
- many players worked with bias `0`

### Search-window widening

The standard visible block did not appear at one fixed delta.

Instead, a lot of late progress came from widening the search window around `personPair`.

This solved many supposedly “special” players without inventing new families.

Examples that eventually turned out to still be `standard_visible`:

- Branthwaite
- Messi
- Zerrouki
- Lindstrom
- Burgzorg
- Dostanic
- van der Heijden
- many screenshot validation players

### Low-anchor variant

Player `352` forced a second generic visible anchor path:

- `layoutVariant = standard_visible_low_anchor`

It still uses the same standard visible field order and same CA/PA logic.

The difference is:

- the block is anchored from a lower duplicate pair rather than the default `personPair` neighborhood

This was introduced only after controlled save edits for `352`.

It is **not** a hardcoded player profile.

## Screenshot Validation For Visible Attributes

The project used a screenshot sanity set to make sure generic decoding was actually correct and not just “plausible”.

Known validated examples included:

- `352`
- `2000226573`
- `91003875`
- `2000414623`
- `37058817`
- `59136080`
- `14004589`
- `85136376`

Important lesson:

- a generic decoder is only trustworthy after it matches screenshot-visible values exactly
- the visible decoder got materially better only after repeated screenshot regression checks

By the end of this phase, the generic standard visible path was trusted for the discovered player set.

## Current Ability / Potential Ability

### Why CA/PA was delayed

At first, CA/PA was only known from Trauner’s separate general-info block. That was not enough to wire it in generically.

The same mistake as early visible-attribute decoding had to be avoided:

- broad coverage
- wrong values

So CA/PA was only generalized after dedicated one-field CA/PA saves.

### Proven generic CA/PA rule

For the generic standard visible path:

- `current_ability` is at `standardStart - 41`
- `potential_ability` is at `standardStart - 39`
- both are raw little-endian `u16`

This was validated across multiple players from different shapes, including:

- standard-visible control players
- `13158416` Aidoo
- low-anchor `352`

### Validation strategy

The generic CA/PA rule was proven using controlled save files where:

- `current ability -> 1`
- `potential ability -> 200`

Players used during that validation included:

- `2000531389`
- `51073017`
- `2000226573`
- `13158416`
- `352`

### Important cleanup use

A very useful later filter was:

- if a discovered “player” has neither CA nor PA, reject it

This removed a number of false positives cleanly.

### Confidence conclusion

By the end of this phase:

- CA/PA was considered reliable for `standard_visible`
- CA/PA was also considered reliable for `standard_visible_low_anchor`
- CA/PA was good enough to import into H2 for the main extractor path

## Generic Name Resolution

### Initial state

Trauner name resolution existed first.

In the Trauner-specific exporter, names were resolved by:

- reading local name IDs near the player block
- resolving them through save string tables

The generic problem was much harder because:

- many numeric IDs exist in multiple string tables
- not every player uses the same local name-reference delta
- some players use common/display name as the preferred name
- legal full names and display names can differ significantly

### Final generic strategy

The generic resolver in `GenericPlayerSubsetExtractor.java` does this:

1. scan a local delta range before `personPair`
2. interpret candidates as:
   - `u32 firstNameId`
   - `+5` bytes: `u32 lastNameId`
   - `+10` bytes: possible common-name ID
3. resolve those IDs against:
   - first-name table
   - surname table
   - common-name table
4. score candidates by:
   - exact known delta
   - string-table score
   - common-name coherence
   - inline full-name string nearby
   - structural marker bytes like `FF FF FF FF`

### Name tables

The current extractor scans separate payload windows for:

- first names
- last names
- common names

Current configured ranges in `GenericPlayerSubsetExtractor.java`:

- first names:
  - `49_000_000 .. 53_550_000`
- surnames:
  - `53_500_000 .. 63_300_000`
- common names:
  - `63_500_000 .. 66_000_000`

These ranges were widened incrementally during reverse engineering, especially surname scanning.

### Delta-driven approach

The biggest insight for names:

- most players can be resolved generically if the local delta is known
- the correct path was to keep adding exact proven deltas, not to open the entire `-500 .. -200` band blindly

Blind widening produced many bad snaps like:

- wrong nearby legal-name pairs
- junk common-name hits
- regressions where previously correct players became wrong

So the stable approach became:

- prove a delta with a name-only edited save or a very clear debug candidate
- add only that exact delta

### Known-name deltas

The current extractor has a large `KNOWN_NAME_DELTAS` array.

That list is the distilled result of many resolved players and name-only save edits.

If name resolution breaks in the future, this array is one of the first places to inspect.

### Common name policy

This was an explicit user preference:

- if a player has a common/display name, that is good enough
- full legal reconstruction is not required to be preferred over common name

So final display-name behavior became:

1. prefer `commonName` if present and coherent
2. otherwise use `firstName + lastName`
3. otherwise use inline full-name fallback

Examples:

- `Dudu`
- `Hulk`
- `Cássio`
- `Rodrygo`
- `Allan`
- `Felipe Anderson`
- `Lucas Paquetá`
- `Bento`
- `Walace`
- `Arthur`

### Inline-name fallback

Some records contain a useful inline full-name string near the local name pair.

This is used to:

- improve candidate ranking
- validate that first and last really belong together
- supply a fallback `fullName` when needed

### Low-anchor inline fallback

Player `352` forced another name path:

- normal local first/last pair did not resolve him cleanly
- a low-anchor inline full-name scan did

This is implemented as `resolveLowAnchorInlineName(...)`.

That path is intentionally narrow and only used when:

- the normal resolver fails
- the player uses `standard_visible_low_anchor`

### Final state reached

By the end of this phase:

- unresolved-name count reached `0`
- one last bad resolution remained briefly for `91184426`
- after adding exact delta `-310`, that too resolved correctly as `Angelo Stiller`

At that point:

- there were no unresolved names left in the live extractor output

## Important Debug/Probe Workflow

### For names

Use:

- [NameResolverDebugProbe.java](src/main/java/com/fm26/save/analysis/NameResolverDebugProbe.java)

Typical usage:

```bash
java -cp target/classes:/home/jelmer/.m2/repository/com/github/luben/zstd-jni/1.5.5-10/zstd-jni-1.5.5-10.jar \
  com.fm26.save.analysis.NameResolverDebugProbe \
  games/Feyenoord_after.fm <playerId> [<playerId>...]
```

What to look for:

- candidate `delta`
- `first`
- `last`
- `common`
- `inline`
- `score`

If the correct candidate is obvious and the delta is not in `KNOWN_NAME_DELTAS`, promote that delta.

### For visible attributes

Primary generic validation file:

- [StandardVisibleBlockProbe.java](src/main/java/com/fm26/save/analysis/StandardVisibleBlockProbe.java)

This was the probe that proved the standard visible family and bias-based decode.

### For current extractor output

Use:

```bash
java -cp target/classes:/home/jelmer/.m2/repository/com/github/luben/zstd-jni/1.5.5-10/zstd-jni-1.5.5-10.jar \
  com.fm26.save.analysis.GenericPlayerSubsetExtractor \
  games/Feyenoord_after.fm /tmp/generic_subset_players.json
```

This output should always be treated as the current source of truth.

Do not rely on stale unresolved-ID lists from earlier runs.

## Mistakes To Avoid

### 1. Using stale unresolved-ID lists

This caused confusion multiple times.

Rule:

- always rerun the extractor before sampling unresolved names

### 2. Blindly widening delta ranges

This created many bad name regressions.

Rule:

- do not “accept everything between X and Y”
- promote only proven exact deltas

### 3. Trusting counts from old runs

The unresolved count can change between runs because:

- code changed
- resolver ranking changed
- stale JSON was used previously

Rule:

- only the latest `/tmp/generic_subset_players.json` matters

### 4. Forcing broad fallbacks

At least one broad name fallback caused major regressions and had to be reverted.

Rule:

- if a fallback fixes a few names but breaks many others, revert it
- prefer exact local deltas and narrow overrides

## H2 Import

The extractor was later wired into H2 via the Spring Boot app.

Relevant files:

- [schema.sql](src/main/resources/schema.sql)
- [PlayerImportService.java](src/main/java/com/fm26/save/service/PlayerImportService.java)
- [PlayerImportRunner.java](src/main/java/com/fm26/save/service/PlayerImportRunner.java)
- [PlayerController.java](src/main/java/com/fm26/save/web/PlayerController.java)

The import is based on the extractor output, so if extractor logic changes:

- rerun import
- or restart the app if import happens on startup

## What Is Considered Proven

These parts are considered genuinely proven and safe enough to trust:

- generic visible attributes for discovered players via `standard_visible`
- generic visible attributes for the low-anchor case via `standard_visible_low_anchor`
- CA/PA for the standard visible path:
  - `current_ability = standardStart - 41`
  - `potential_ability = standardStart - 39`
- names via:
  - exact local deltas in `KNOWN_NAME_DELTAS`
  - common-name preference when coherent
  - low-anchor inline fallback for `352`

## What Remains Less Ideal

Even though names are currently fully resolved in the live run, the name resolver is still somewhat ranking-sensitive.

That means:

- future scoring changes can reintroduce regressions if done carelessly
- exact deltas remain the safest way to extend or repair it

If the system ever regresses:

1. rerun extractor
2. rerun `NameResolverDebugProbe` for the broken ID
3. compare the correct candidate to current `KNOWN_NAME_DELTAS`
4. promote the exact delta if needed
5. avoid broad fallback changes unless strictly necessary

## Concrete Resume Point

If work resumes later and this file is referenced, the shortest “reboot” is:

1. read this file
2. inspect:
   - `KNOWN_NAME_DELTAS`
   - `resolveName(...)`
   - `resolveLowAnchorInlineName(...)`
   - standard visible decode logic
   - CA/PA offsets relative to `standardStart`
3. rerun:

```bash
mvn -q -DskipTests compile
java -cp target/classes:/home/jelmer/.m2/repository/com/github/luben/zstd-jni/1.5.5-10/zstd-jni-1.5.5-10.jar \
  com.fm26.save.analysis.GenericPlayerSubsetExtractor \
  games/Feyenoord_after.fm /tmp/generic_subset_players.json
```

4. if a name breaks, run:

```bash
java -cp target/classes:/home/jelmer/.m2/repository/com/github/luben/zstd-jni/1.5.5-10/zstd-jni-1.5.5-10.jar \
  com.fm26.save.analysis.NameResolverDebugProbe \
  games/Feyenoord_after.fm <playerId>
```

That is enough to resume this work quickly.
