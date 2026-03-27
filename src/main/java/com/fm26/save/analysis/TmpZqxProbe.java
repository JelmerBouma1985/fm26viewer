package com.fm26.save.analysis;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.Map;

public final class TmpZqxProbe {

    public static void main(String[] args) throws Exception {
        int playerId = args.length > 1 ? Integer.parseInt(args[1]) : -1;
        Class<?> extractor = GenericPlayerSubsetExtractor.class;
        Method loadPayload = extractor.getDeclaredMethod("loadPayload", Path.class);
        loadPayload.setAccessible(true);
        Method buildNameTables = extractor.getDeclaredMethod("buildNameTables", byte[].class);
        buildNameTables.setAccessible(true);

        Class<?> nameTablesClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$NameTables");
        Method firstNamesMethod = nameTablesClass.getDeclaredMethod("firstNames");
        Method lastNamesMethod = nameTablesClass.getDeclaredMethod("lastNames");
        Method commonNamesMethod = nameTablesClass.getDeclaredMethod("commonNames");
        Method earlyCommonNamesMethod = nameTablesClass.getDeclaredMethod("earlyCommonNames");
        Method looseLastNamesMethod = nameTablesClass.getDeclaredMethod("looseLastNames");
        firstNamesMethod.setAccessible(true);
        lastNamesMethod.setAccessible(true);
        commonNamesMethod.setAccessible(true);
        earlyCommonNamesMethod.setAccessible(true);
        looseLastNamesMethod.setAccessible(true);

        Class<?> scoredStringClass = Class.forName("com.fm26.save.analysis.GenericPlayerSubsetExtractor$ScoredString");
        Method valueMethod = scoredStringClass.getDeclaredMethod("value");
        Method scoreMethod = scoredStringClass.getDeclaredMethod("score");
        valueMethod.setAccessible(true);
        scoreMethod.setAccessible(true);

        byte[] payload = (byte[]) loadPayload.invoke(null, Path.of(args[0]));
        Object tables = buildNameTables.invoke(null, (Object) payload);
        dump("first", (Map<Integer, Object>) firstNamesMethod.invoke(tables), valueMethod, scoreMethod);
        dump("last", (Map<Integer, Object>) lastNamesMethod.invoke(tables), valueMethod, scoreMethod);
        dump("common", (Map<Integer, Object>) commonNamesMethod.invoke(tables), valueMethod, scoreMethod);
        dump("earlyCommon", (Map<Integer, Object>) earlyCommonNamesMethod.invoke(tables), valueMethod, scoreMethod);
        dumpId("last", (Map<Integer, Object>) lastNamesMethod.invoke(tables), 5769, valueMethod, scoreMethod);
        dumpId("looseLast", (Map<Integer, Object>) looseLastNamesMethod.invoke(tables), 5769, valueMethod, scoreMethod);
        int personPair = playerId > 0 ? findDuplicatePairOffset(payload, playerId, 65_000_000, 90_000_000) : -1;
        System.out.println("personPair=" + personPair);
        findRaw(payload, "van Kilsdonk", personPair);
        findRaw(payload, "Kilsdonk", personPair);
        findRaw(payload, "Hou Sæter", personPair);
        findRaw(payload, "John Hou Sæter", personPair);
        byte[] needle = "Zqx".getBytes();
        for (int i = 0; i <= payload.length - needle.length; i++) {
            if (payload[i] == needle[0] && payload[i + 1] == needle[1] && payload[i + 2] == needle[2]) {
                System.out.println("raw offset=" + i);
                int idStart = i - 8;
                if (idStart >= 0) {
                    int stringId = (payload[idStart] & 0xFF)
                            | ((payload[idStart + 1] & 0xFF) << 8)
                            | ((payload[idStart + 2] & 0xFF) << 16)
                            | ((payload[idStart + 3] & 0xFF) << 24);
                    int length = (payload[idStart + 4] & 0xFF)
                            | ((payload[idStart + 5] & 0xFF) << 8)
                            | ((payload[idStart + 6] & 0xFF) << 16)
                            | ((payload[idStart + 7] & 0xFF) << 24);
                    System.out.println("stringId=" + stringId + " length=" + length);
                    if (personPair > 0) {
                        scanReferences(payload, stringId, personPair);
                    }
                }
                int start = Math.max(0, i - 24);
                int end = Math.min(payload.length, i + 40);
                StringBuilder hex = new StringBuilder();
                StringBuilder ascii = new StringBuilder();
                for (int j = start; j < end; j++) {
                    hex.append(String.format("%02X ", payload[j] & 0xFF));
                    int c = payload[j] & 0xFF;
                    ascii.append(c >= 32 && c <= 126 ? (char) c : '.');
                }
                System.out.println("hex=" + hex);
                System.out.println("ascii=" + ascii);
            }
        }
    }

    private static void dump(String label, Map<Integer, Object> map, Method valueMethod, Method scoreMethod) throws Exception {
        for (Map.Entry<Integer, Object> e : map.entrySet()) {
            String value = (String) valueMethod.invoke(e.getValue());
            if (value != null && value.toLowerCase().contains("zqx")) {
                System.out.println(label + " id=" + e.getKey() + " value=" + value + " score=" + scoreMethod.invoke(e.getValue()));
            }
        }
    }

    private static void dumpId(String label, Map<Integer, Object> map, int id, Method valueMethod, Method scoreMethod) throws Exception {
        Object value = map.get(id);
        if (value != null) {
            System.out.println(label + "[" + id + "]=" + valueMethod.invoke(value) + " score=" + scoreMethod.invoke(value));
        } else {
            System.out.println(label + "[" + id + "]=null");
        }
    }

    private static void findRaw(byte[] payload, String value, int personPair) {
        byte[] needle = value.getBytes();
        int idx = indexOf(payload, needle);
        System.out.println("find [" + value + "] => " + idx);
        if (idx >= 8) {
            int stringId = u32le(payload, idx - 8);
            int length = u32le(payload, idx - 4);
            System.out.println("  stringId=" + stringId + " length=" + length);
            if (personPair > 0) {
                scanReferences(payload, stringId, personPair);
            }
        }
    }

    private static void scanReferences(byte[] payload, int stringId, int personPair) {
        System.out.println("  refs near personPair for stringId=" + stringId);
        for (int off = Math.max(0, personPair - 3000); off < Math.min(payload.length - 4, personPair + 500); off++) {
            if (u32le(payload, off) == stringId) {
                System.out.println("    ref at " + off + " delta=" + (off - personPair));
            }
        }
    }

    private static int findDuplicatePairOffset(byte[] payload, int playerId, int minOffset, int maxOffset) {
        for (int offset = Math.max(0, minOffset); offset + 8 <= payload.length && offset < maxOffset; offset++) {
            if (u32le(payload, offset) == playerId && u32le(payload, offset + 4) == playerId) {
                return offset;
            }
        }
        return -1;
    }

    private static int u32le(byte[] payload, int offset) {
        return (payload[offset] & 0xFF)
                | ((payload[offset + 1] & 0xFF) << 8)
                | ((payload[offset + 2] & 0xFF) << 16)
                | ((payload[offset + 3] & 0xFF) << 24);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
