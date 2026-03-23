package com.fm26.save.web;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/players")
public class PlayerController {

    private final JdbcTemplate jdbcTemplate;

    public PlayerController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    public List<Map<String, Object>> listPlayers(
            @RequestParam(defaultValue = "100") int limit,
            @RequestParam(defaultValue = "0") int offset
    ) {
        return jdbcTemplate.query("""
                select player_id, first_name, last_name, full_name, family, confidence, layout_variant, layout_score, invalid_field_count
                from players
                order by player_id
                limit ? offset ?
                """,
                (rs, rowNum) -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("playerId", rs.getLong("player_id"));
                    row.put("firstName", rs.getString("first_name"));
                    row.put("lastName", rs.getString("last_name"));
                    row.put("fullName", rs.getString("full_name"));
                    row.put("family", rs.getString("family"));
                    row.put("confidence", rs.getString("confidence"));
                    row.put("layoutVariant", rs.getString("layout_variant"));
                    row.put("layoutScore", rs.getInt("layout_score"));
                    row.put("invalidFieldCount", rs.getInt("invalid_field_count"));
                    return row;
                },
                limit,
                offset
        );
    }

    @GetMapping("/{playerId}")
    public Map<String, Object> getPlayer(@PathVariable long playerId) {
        Map<String, Object> player = jdbcTemplate.queryForObject("""
                select player_id, person_pair_offset, extra_pair_offset, first_name, last_name, full_name, discovery_source, family,
                       family_score, confidence, layout_variant, layout_score, invalid_field_count
                from players
                where player_id = ?
                """,
                (rs, rowNum) -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("playerId", rs.getLong("player_id"));
                    row.put("personPairOffset", rs.getInt("person_pair_offset"));
                    row.put("extraPairOffset", rs.getInt("extra_pair_offset"));
                    row.put("firstName", rs.getString("first_name"));
                    row.put("lastName", rs.getString("last_name"));
                    row.put("fullName", rs.getString("full_name"));
                    row.put("discoverySource", rs.getString("discovery_source"));
                    row.put("family", rs.getString("family"));
                    row.put("familyScore", rs.getInt("family_score"));
                    row.put("confidence", rs.getString("confidence"));
                    row.put("layoutVariant", rs.getString("layout_variant"));
                    row.put("layoutScore", rs.getInt("layout_score"));
                    row.put("invalidFieldCount", rs.getInt("invalid_field_count"));
                    return row;
                },
                playerId
        );

        List<Map<String, Object>> fields = jdbcTemplate.query("""
                select field_name, field_value
                from player_fields
                where player_id = ?
                order by field_name
                """,
                (rs, rowNum) -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("name", rs.getString("field_name"));
                    row.put("value", (Integer) rs.getObject("field_value"));
                    return row;
                },
                playerId
        );
        player.put("fields", fields);
        return player;
    }
}
