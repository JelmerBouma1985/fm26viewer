#!/usr/bin/env python3
"""
Extract a full player object from a decompressed FM save frame.

Default frame: out/save_dump/frame_0003.raw.bin
Default player: Erling Haaland (29179241)

Examples:
  python3 extract_player_object.py --player-id 29179241
  python3 extract_player_object.py --player-id 37060952 --pretty
  python3 extract_player_object.py --player-id 7458500 --out messi.json
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ATTRIBUTE_INDEX: Dict[str, int] = {
    # Technical
    "crossing": 0,
    "dribbling": 1,
    "finishing": 2,
    "heading": 3,
    "long_shots": 4,
    "marking": 5,
    "passing": 7,
    "penalty_taking": 8,
    "tackling": 9,
    "technique": 23,
    "corners": 27,
    "free_kick_taking": 35,
    "long_throws": 30,
    "first_touch": 22,
    # Mental
    "anticipation": 17,
    "decisions": 18,
    "positioning": 20,
    "flair": 26,
    "teamwork": 28,
    "work_rate": 29,
    "vision": 10,
    "aggression": 45,
    "bravery": 43,
    "concentration": 53,
    "determination": 51,
    "leadership": 40,
    "composure": 52,
    "off_the_ball": 6,
    # General (non-panel, but stored in the same 54-value vector)
    "left_foot": 24,
    "right_foot": 25,
    # Physical
    "acceleration": 34,
    "agility": 46,
    "balance": 42,
    "jumping_reach": 39,
    "natural_fitness": 50,
    "pace": 38,
    "stamina": 37,
    "strength": 36,
}

TECHNICAL = [
    "corners", "crossing", "dribbling", "finishing", "first_touch", "free_kick_taking",
    "heading", "long_shots", "long_throws", "marking", "passing", "penalty_taking",
    "tackling", "technique",
]

MENTAL = [
    "aggression", "anticipation", "bravery", "composure", "concentration", "decisions",
    "determination", "flair", "leadership", "off_the_ball", "positioning", "teamwork",
    "vision", "work_rate",
]

PHYSICAL = [
    "acceleration", "agility", "balance", "jumping_reach", "natural_fitness",
    "pace", "stamina", "strength",
]


def u32le(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 4], "little", signed=False)


def try_parse_string_entry(buf: bytes, pos: int) -> Optional[Tuple[int, str, int]]:
    if pos < 0 or pos + 12 >= len(buf):
        return None
    sid = u32le(buf, pos)
    n = u32le(buf, pos + 4)
    if sid <= 0 or n < 1 or n > 200:
        return None
    s = pos + 8
    e = s + n
    if e > len(buf):
        return None
    raw = buf[s:e]
    if any(x == 0 or x < 0x20 for x in raw):
        return None
    try:
        txt = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not txt.strip():
        return None
    return sid, txt, 8 + n


def parse_string_table_runs(buf: bytes, min_run_entries: int = 64) -> Dict[int, List[str]]:
    out: Dict[int, List[str]] = {}
    i = 0
    n = len(buf)
    while i + 16 < n:
        e1 = try_parse_string_entry(buf, i)
        if e1 is None:
            i += 1
            continue

        next_base = i + e1[2]
        e2_pos = -1
        for pad in range(4):
            if try_parse_string_entry(buf, next_base + pad) is not None:
                e2_pos = next_base + pad
                break
        if e2_pos < 0:
            i += 1
            continue

        run_start = i
        run_pos = i
        run_count = 0
        while True:
            e = try_parse_string_entry(buf, run_pos)
            if e is None:
                break
            run_count += 1
            nb = run_pos + e[2]
            np = -1
            for pad in range(4):
                if try_parse_string_entry(buf, nb + pad) is not None:
                    np = nb + pad
                    break
            if np < 0:
                run_pos = nb
                break
            run_pos = np

        if run_count >= min_run_entries:
            p = run_start
            for _ in range(run_count):
                e = try_parse_string_entry(buf, p)
                if e is None:
                    break
                sid, txt, size = e
                xs = out.setdefault(sid, [])
                if txt not in xs and len(xs) < 8:
                    xs.append(txt)
                nb = p + size
                np = -1
                for pad in range(4):
                    if try_parse_string_entry(buf, nb + pad) is not None:
                        np = nb + pad
                        break
                if np < 0:
                    break
                p = np
            i = run_pos
        else:
            i += 1
    return out


def looks_like_name_part(s: str) -> bool:
    t = s.strip()
    if len(t) < 2 or len(t) > 60:
        return False
    if any(ch.isdigit() for ch in t):
        return False
    parts = t.split()
    if len(parts) < 1 or len(parts) > 6:
        return False
    lower_ok = {
        "de", "do", "da", "das", "dos", "der", "den", "van", "von", "del", "la", "le", "di",
        "du", "st", "al", "el", "bin", "ibn", "lo", "e"
    }
    for p in parts:
        if len(p) > 20:
            return False
        if not all(ch.isalpha() or ch in "'-." for ch in p):
            return False
        if p[0].isalpha() and p[0].islower() and p.lower() not in lower_ok:
            return False
    return True


def build_name_parts_string_table(buf: bytes) -> Dict[int, List[str]]:
    raw = parse_string_table_runs(buf)
    out: Dict[int, List[str]] = {}
    for sid, vals in raw.items():
        cands = []
        for v in vals:
            t = v.strip()
            if looks_like_name_part(t) and t not in cands:
                cands.append(t)
        if cands:
            out[sid] = cands
    return out


def decode_non_attribute_candidates(buf: bytes, pid_pos: int) -> dict:
    out: dict = {}
    s = max(0, pid_pos - 0x2000)
    e = min(len(buf), pid_pos + 0x600)

    # Nearby printable UTF-8 strings (length-prefixed) to inspect profile metadata around record.
    near_strings = []
    i = s
    while i + 4 < e:
        n = u32le(buf, i)
        if 3 <= n <= 120 and i + 4 + n <= e:
            raw = buf[i + 4:i + 4 + n]
            if all(x >= 0x20 for x in raw):
                try:
                    txt = raw.decode("utf-8")
                    near_strings.append({
                        "offset": f"0x{i:X}",
                        "distance": pid_pos - (i + 4 + n),
                        "value": txt
                    })
                except UnicodeDecodeError:
                    pass
        i += 1
    near_strings.sort(key=lambda x: abs(x["distance"]))
    out["nearby_length_prefixed_strings"] = near_strings[:200]

    # Candidate scalar values (u32) in a local window for CA/PA/reputation-like fields.
    scalar_candidates = []
    for off in range(s, e - 4):
        v = u32le(buf, off)
        if 0 <= v <= 20000:
            scalar_candidates.append({
                "offset": f"0x{off:X}",
                "distance": pid_pos - off,
                "value_u32": v
            })
    scalar_candidates.sort(key=lambda x: (abs(x["distance"]), x["value_u32"]))
    out["nearby_u32_candidates_0_20000"] = scalar_candidates[:500]

    # Structured name-id refs near pid: useful for first/second name decoding.
    tokens_by_id = build_name_parts_string_table(buf)
    refs = []
    scan_start = max(0, pid_pos - 0x1000)
    scan_end = max(scan_start, pid_pos - 4)
    for off in range(scan_start, scan_end):
        sid = u32le(buf, off)
        cands = tokens_by_id.get(sid)
        if cands:
            refs.append((off, sid, cands))
    out["name_sid_ref_count"] = len(refs)

    pair_candidates = []
    for j in range(len(refs) - 1, 0, -1):
        l_off, l_sid, l_cands = refs[j]
        d = pid_pos - l_off
        if d < 64 or d > 2048:
            continue
        for i in range(j - 1, -1, -1):
            f_off, f_sid, f_cands = refs[i]
            if f_sid == l_sid:
                continue
            gap = l_off - f_off
            if gap < 0 or gap > 256:
                continue
            raw_gap5 = gap == 5
            b4 = buf[f_off + 4] if f_off + 4 < pid_pos else -1
            gap5 = raw_gap5 and b4 == 0
            sentinel = False
            if raw_gap5 and l_off + 7 < pid_pos:
                sentinel = (buf[l_off + 4] == 0 and buf[l_off + 5] == 0xFF and buf[l_off + 6] == 0xFF and buf[l_off + 7] == 0xFF)
            pair_candidates.append({
                "first_sid": f_sid,
                "last_sid": l_sid,
                "first_candidates": f_cands,
                "last_candidates": l_cands,
                "first_offset": f"0x{f_off:X}",
                "last_offset": f"0x{l_off:X}",
                "distance_to_pid": d,
                "gap": gap,
                "gap5_zero": gap5,
                "sentinel_after_last": sentinel,
            })
    pair_candidates.sort(key=lambda x: (
        0 if x["sentinel_after_last"] else 1,
        0 if x["gap5_zero"] else 1,
        abs(x["distance_to_pid"] - 260),
        x["distance_to_pid"],
        x["gap"],
    ))
    out["name_sid_pair_candidates"] = pair_candidates[:120]
    out["best_name_sid_pair_candidate"] = pair_candidates[0] if pair_candidates else None

    return out


def resolve_name_components(nearest_name: Optional[dict], non_attr: Optional[dict]) -> Optional[dict]:
    if not non_attr:
        return None
    best = non_attr.get("best_name_sid_pair_candidate")
    if not best:
        return None

    first_cands = list(best.get("first_candidates") or [])
    last_cands = list(best.get("last_candidates") or [])
    nearest_full_name = (nearest_name or {}).get("value") if nearest_name else None
    nearest_distance = (nearest_name or {}).get("distance") if nearest_name else None
    full_low = nearest_full_name.lower() if nearest_full_name else ""

    # Empirically in FM26 saves:
    # - first-name SIDs map best to candidate[0]
    # - second-name SIDs map best to candidate[1] when present
    # If a trustworthy nearby full name exists, prefer matches against it.
    first = first_cands[0] if first_cands else None
    second = last_cands[1] if len(last_cands) > 1 else (last_cands[0] if last_cands else None)

    nearest_trustworthy = nearest_full_name is not None and nearest_distance is not None and nearest_distance <= 700
    if nearest_trustworthy:
        for c in first_cands:
            if c and c.lower() in full_low:
                first = c
                break
        for c in last_cands:
            if c and c.lower() in full_low:
                second = c
                break

    if nearest_trustworthy and first and second and first.lower() in full_low and second.lower() in full_low:
        full_name = nearest_full_name
    elif first and second:
        full_name = f"{first} {second}"
    elif nearest_trustworthy:
        full_name = nearest_full_name
    else:
        full_name = None

    return {
        "first_name": first,
        "second_name": second,
        "full_name": full_name,
        "nearest_full_name_raw": nearest_full_name,
        "nearest_full_name_distance": nearest_distance,
        "first_name_candidates": first_cands,
        "second_name_candidates": last_cands,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract full player object from decompressed save frame")
    p.add_argument("--frame", default="out/save_dump/frame_0003.raw.bin", help="Path to decompressed frame binary")
    p.add_argument("--player-id", type=int, required=True, help="FM player id")
    p.add_argument("--max-back", type=lambda x: int(x, 0), default=0x40000, help="Max bytes to search backward from pid")
    p.add_argument("--out", help="Optional JSON output file")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    return p.parse_args()


def is_attr_byte(x: int) -> bool:
    return 0 <= x <= 100 and x % 5 == 0


def looks_like_person_name_loose(s: str) -> bool:
    t = s.strip()
    if len(t) < 5 or len(t) > 80:
        return False
    if " " not in t:
        return False
    if any(ord(ch) < 0x20 for ch in t):
        return False
    if any(ch.isdigit() for ch in t):
        return False
    lower = t.lower()
    stop_words = (" fc", " afc", " club", " academy", " athletic", " football", " university")
    return not any(w in lower for w in stop_words)


def find_nearest_name_before(buf: bytes, pos: int, window: int = 0x6000) -> Optional[dict]:
    start = max(0, pos - window)
    best_name: Optional[str] = None
    best_dist = 1 << 30
    best_offset = -1

    i = start
    while i + 4 < pos:
        n = int.from_bytes(buf[i:i + 4], "little", signed=False)
        if n < 5 or n > 80:
            i += 1
            continue
        s = i + 4
        e = s + n
        if e > pos:
            i += 1
            continue
        raw = buf[s:e]
        if any(x == 0 or x < 0x20 for x in raw):
            i += 1
            continue
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            i += 1
            continue
        if not looks_like_person_name_loose(txt):
            i += 1
            continue
        dist = pos - e
        if dist < best_dist:
            best_dist = dist
            best_name = txt
            best_offset = i
        i += 1

    if best_name is None:
        return None
    return {
        "value": best_name,
        "distance": best_dist,
        "name_len_field_offset": f"0x{best_offset:X}",
    }


def find_pid_hits(buf: bytes, player_id: int) -> List[int]:
    pat = struct.pack("<II", player_id, player_id)
    hits: List[int] = []
    i = 0
    while True:
        i = buf.find(pat, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    return hits


def find_attr_before_pid(buf: bytes, pid_pos: int, max_back: int) -> int:
    start = max(0, pid_pos - max_back)

    i = pid_pos - 1
    while i >= start:
        if not is_attr_byte(buf[i]):
            i -= 1
            continue

        streak_end = i + 1
        streak_start = i
        while streak_start > start and is_attr_byte(buf[streak_start - 1]):
            streak_start -= 1

        streak_len = streak_end - streak_start
        if streak_len >= 54 and streak_start + 54 <= pid_pos:
            non_zero = sum(1 for k in range(54) if buf[streak_start + k] != 0)
            if non_zero >= 45:
                return streak_start

        i = streak_start - 1

    return -1


def extract_vector(buf: bytes, attr_pos: int) -> List[int]:
    return [buf[attr_pos + k] // 5 for k in range(54)]


def build_named_attributes(vec: List[int]) -> dict:
    tech = {k: vec[ATTRIBUTE_INDEX[k]] for k in TECHNICAL}
    mental = {k: vec[ATTRIBUTE_INDEX[k]] for k in MENTAL}
    physical = {k: vec[ATTRIBUTE_INDEX[k]] for k in PHYSICAL}

    used = set(ATTRIBUTE_INDEX.values())
    unmapped = {f"index_{i:02d}": vec[i] for i in range(54) if i not in used}

    flat = {k: vec[i] for k, i in ATTRIBUTE_INDEX.items()}
    return {
        "flat": flat,
        "technical": tech,
        "mental": mental,
        "physical": physical,
        "unmapped": unmapped,
    }


def map_non_attributes(
        buf: bytes,
        attr_pos: Optional[int],
        pid_pos: int,
        marker: Optional[int],
        vec: Optional[List[int]]
) -> Optional[dict]:
    if attr_pos is None:
        return None

    def u8(rel: int) -> int:
        return buf[attr_pos + rel]

    def u16(rel: int) -> int:
        o = attr_pos + rel
        return int.from_bytes(buf[o:o + 2], "little", signed=False)

    ca_u16 = u16(-39)
    pa_u16 = u16(-37)
    ca_u8 = u8(79)
    pa_u8 = u8(80)
    height_cm = u16(82)

    out = {
        "current_ability": {
            "value": ca_u16,
            "offset_u16": f"0x{attr_pos - 39:X}",
            "mirror_u8_value": ca_u8,
            "mirror_u8_offset": f"0x{attr_pos + 79:X}",
            "confidence": "high" if ca_u16 == ca_u8 else "medium",
        },
        "potential_ability": {
            "value": pa_u16,
            "offset_u16": f"0x{attr_pos - 37:X}",
            "mirror_u8_value": pa_u8,
            "mirror_u8_offset": f"0x{attr_pos + 80:X}",
            "confidence": "high" if pa_u16 == pa_u8 else "medium",
        },
        "height_cm": {
            "value": height_cm,
            "offset_u16": f"0x{attr_pos + 82:X}",
            "confidence": "high",
        },
        "game_reputation_scaled": {
            "home": {
                "value": u16(-45),
                "offset_u16": f"0x{attr_pos - 45:X}",
            },
            "current": {
                "value": u16(-43),
                "offset_u16": f"0x{attr_pos - 43:X}",
            },
            "world": {
                "value": u16(-41),
                "offset_u16": f"0x{attr_pos - 41:X}",
            },
            "confidence": "medium",
        },
        "record_markers": {
            "pid_plus_8_marker": marker,
            "attr_plus_84_u8": u8(84),
            "confidence": "low",
        },
    }
    if vec is not None and len(vec) >= 26:
        out["footedness"] = {
            "left_foot": {
                "value": vec[24],
                "vector_index": 24,
                "confidence": "high",
            },
            "right_foot": {
                "value": vec[25],
                "vector_index": 25,
                "confidence": "high",
            },
        }
    return out


def build_hit_object(buf: bytes, pid_pos: int, max_back: int) -> dict:
    marker = buf[pid_pos + 8] if pid_pos + 8 < len(buf) else None
    name = find_nearest_name_before(buf, pid_pos)
    attr_pos = find_attr_before_pid(buf, pid_pos, max_back)

    out = {
        "pid_offset": f"0x{pid_pos:X}",
        "pid_offset_int": pid_pos,
        "marker": marker,
        "nearest_name": name,
        "attr_offset": None,
        "attr_offset_int": None,
        "attr_delta": None,
        "vector_54": None,
        "attributes": None,
        "mapped_non_attributes": None,
        "non_attribute_candidates": None,
        "name_components": None,
    }

    if attr_pos >= 0:
        vec = extract_vector(buf, attr_pos)
        out["attr_offset"] = f"0x{attr_pos:X}"
        out["attr_offset_int"] = attr_pos
        out["attr_delta"] = pid_pos - (attr_pos + 54)
        out["vector_54"] = vec
        out["attributes"] = build_named_attributes(vec)
        out["mapped_non_attributes"] = map_non_attributes(buf, attr_pos, pid_pos, marker, vec)

    out["non_attribute_candidates"] = decode_non_attribute_candidates(buf, pid_pos)
    out["name_components"] = resolve_name_components(name, out["non_attribute_candidates"])

    return out


def pick_best_hit(hits: List[dict]) -> Optional[dict]:
    if not hits:
        return None

    def score(h: dict) -> tuple:
        # Lower is better.
        has_attr = 0 if h["attr_offset_int"] is not None else 1
        marker_ok = 0 if h["marker"] in (1, 2) else 1
        delta = h["attr_delta"] if h["attr_delta"] is not None else 10**9
        return (has_attr, marker_ok, delta)

    return sorted(hits, key=score)[0]


def main() -> int:
    args = parse_args()
    frame_path = Path(args.frame)
    if not frame_path.is_file():
        print(f"ERROR: frame file not found: {frame_path}")
        return 2

    buf = frame_path.read_bytes()
    pid_hits = find_pid_hits(buf, args.player_id)

    hit_objects = [build_hit_object(buf, p, args.max_back) for p in pid_hits]
    best = pick_best_hit(hit_objects)

    obj = {
        "frame": str(frame_path),
        "player_id": args.player_id,
        "pid_hit_count": len(pid_hits),
        "selected_hit": best,
        "all_hits": hit_objects,
    }

    text = json.dumps(obj, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.out:
        Path(args.out).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
