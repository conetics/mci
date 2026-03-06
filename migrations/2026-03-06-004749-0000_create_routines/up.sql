CREATE TABLE routines (
    pid                 UUID            PRIMARY KEY,
    name                TEXT            NOT NULL,
    description         TEXT            NOT NULL DEFAULT '',
    code_hash           TEXT            NOT NULL,
    environment         TEXT            NOT NULL,
    env_config          JSONB           NOT NULL DEFAULT '{}',
    priority            SMALLINT        NOT NULL DEFAULT 128 CONSTRAINT priority_range CHECK (priority BETWEEN 0 AND 255),
    timeout_ms          BIGINT          CONSTRAINT timeout_positive CHECK (timeout_ms > 0),
    retry_max_attempts  SMALLINT        CONSTRAINT retry_max_attempts_positive CHECK (retry_max_attempts >= 1),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_routines_name ON routines (name);
CREATE INDEX idx_routines_description ON routines USING GIN (to_tsvector('english', description));
CREATE INDEX idx_routines_environment ON routines (environment);
CREATE INDEX idx_routines_priority ON routines (priority ASC);
CREATE INDEX idx_routines_created_at ON routines (created_at ASC);
CREATE INDEX idx_routines_updated_at ON routines (updated_at ASC);
