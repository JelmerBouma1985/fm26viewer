package com.fm26.save.service;

import com.fm26.save.analysis.GenericPlayerSubsetExtractor;
import com.fm26.save.analysis.GenericPlayerSubsetExtractor.ExtractedPlayer;
import com.fm26.save.analysis.GenericPlayerSubsetExtractor.ExtractionResult;
import com.fm26.save.config.SaveImportProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class PlayerImportService {

    private static final Logger log = LoggerFactory.getLogger(PlayerImportService.class);

    private final JdbcTemplate jdbcTemplate;
    private final SaveImportProperties properties;

    public PlayerImportService(JdbcTemplate jdbcTemplate, SaveImportProperties properties) {
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
    }

    public ExtractionResult importConfiguredSave() throws IOException {
        Path save = Path.of(properties.getSavePath());
        log.info("Importing save into H2 from {}", save);
        ExtractionResult result = GenericPlayerSubsetExtractor.extract(save);
        replaceDatabaseContents(result.players());
        log.info("Imported {} players from {}", result.players().size(), save);
        return result;
    }

    private void replaceDatabaseContents(List<ExtractedPlayer> players) {
        jdbcTemplate.update("alter table players add column if not exists first_name varchar(255)");
        jdbcTemplate.update("alter table players add column if not exists last_name varchar(255)");
        jdbcTemplate.update("alter table players add column if not exists full_name varchar(512)");
        jdbcTemplate.update("delete from player_fields");
        jdbcTemplate.update("delete from players");

        List<Object[]> playerRows = new ArrayList<>(players.size());
        List<Object[]> fieldRows = new ArrayList<>();
        for (ExtractedPlayer player : players) {
            playerRows.add(new Object[]{
                    Integer.toUnsignedLong(player.id()),
                    player.personPair(),
                    player.extraPair(),
                    player.firstName(),
                    player.lastName(),
                    player.fullName(),
                    player.discoverySource(),
                    player.family(),
                    player.familyScore(),
                    player.confidence(),
                    player.layoutVariant(),
                    player.layoutScore(),
                    player.invalidFieldCount()
            });
            for (Map.Entry<String, Integer> field : player.fields().entrySet()) {
                fieldRows.add(new Object[]{
                        Integer.toUnsignedLong(player.id()),
                        field.getKey(),
                        field.getValue()
                });
            }
        }

        jdbcTemplate.batchUpdate("""
                insert into players (
                    player_id, person_pair_offset, extra_pair_offset, first_name, last_name, full_name, discovery_source, family,
                    family_score, confidence, layout_variant, layout_score, invalid_field_count
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, playerRows);

        jdbcTemplate.batchUpdate("""
                insert into player_fields (player_id, field_name, field_value)
                values (?, ?, ?)
                """, fieldRows);
    }
}
