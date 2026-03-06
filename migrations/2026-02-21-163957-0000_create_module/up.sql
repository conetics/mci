CREATE TYPE module_type AS ENUM (
    'language',
    'sandbox',
    'interceptor',
    'proxy',
    'hook'
);

CREATE TABLE modules (
    id          VARCHAR(64)  PRIMARY KEY NOT NULL,
    type        module_type  NOT NULL,
    is_enabled  BOOLEAN      NOT NULL DEFAULT FALSE,
    name        VARCHAR(64)  NOT NULL,
    description TEXT         NOT NULL,
    digest      TEXT         NOT NULL UNIQUE,
    source_url  TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_modules_updated_at
    BEFORE UPDATE ON modules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_modules_type        ON modules (type);
CREATE INDEX idx_modules_is_enabled  ON modules (is_enabled);
CREATE INDEX idx_modules_name        ON modules (name);
CREATE INDEX idx_modules_description ON modules USING GIN (to_tsvector('english', description));
