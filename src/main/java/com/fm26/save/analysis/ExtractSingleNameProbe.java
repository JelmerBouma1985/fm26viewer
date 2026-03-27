package com.fm26.save.analysis;

import java.nio.file.Path;

public final class ExtractSingleNameProbe {

    private ExtractSingleNameProbe() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: ExtractSingleNameProbe <save.fm> <playerId>");
        }
        Path save = Path.of(args[0]);
        int playerId = Integer.parseInt(args[1]);
        GenericPlayerSubsetExtractor.ExtractionResult result = GenericPlayerSubsetExtractor.extract(save);
        for (GenericPlayerSubsetExtractor.ExtractedPlayer player : result.players()) {
            if (player.id() == playerId) {
                System.out.println(player.id()
                        + "|" + player.personPair()
                        + "|" + player.firstName()
                        + "|" + player.lastName()
                        + "|" + player.fullName());
                return;
            }
        }
        System.out.println("not found");
    }
}
