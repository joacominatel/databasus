-- +goose Up
-- +goose StatementBegin

CREATE TABLE database_ssh_tunnels (
    id                         UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id                UUID    NOT NULL,
    host                       TEXT    NOT NULL,
    port                       INT     NOT NULL DEFAULT 22,
    username                   TEXT    NOT NULL,
    password                   TEXT    NOT NULL DEFAULT '',
    private_key                TEXT    NOT NULL DEFAULT '',
    private_key_passphrase     TEXT    NOT NULL DEFAULT '',
    host_key_fingerprint       TEXT    NOT NULL DEFAULT '',
    should_skip_host_key_check BOOLEAN NOT NULL DEFAULT FALSE
);

ALTER TABLE database_ssh_tunnels
    ADD CONSTRAINT fk_database_ssh_tunnels_database_id
    FOREIGN KEY (database_id)
    REFERENCES databases (id)
    ON DELETE CASCADE;

CREATE UNIQUE INDEX uq_database_ssh_tunnels_database_id
    ON database_ssh_tunnels (database_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE database_ssh_tunnels;

-- +goose StatementEnd
