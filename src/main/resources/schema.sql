create table if not exists players (
    player_id bigint primary key,
    person_pair_offset int not null,
    extra_pair_offset int not null,
    first_name varchar(255),
    last_name varchar(255),
    full_name varchar(512),
    discovery_source varchar(32) not null,
    family varchar(64) not null,
    family_score int not null,
    confidence varchar(32) not null,
    layout_variant varchar(64) not null,
    layout_score int not null,
    invalid_field_count int not null
);

create table if not exists player_fields (
    player_id bigint not null,
    field_name varchar(64) not null,
    field_value int,
    primary key (player_id, field_name),
    constraint fk_player_fields_player
        foreign key (player_id) references players(player_id)
        on delete cascade
);

create index if not exists idx_players_family on players(family);
create index if not exists idx_players_confidence on players(confidence);
create index if not exists idx_player_fields_name on player_fields(field_name);
