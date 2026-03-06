CREATE TABLE definitions (
    id          VARCHAR(64)  PRIMARY KEY NOT NULL,
    type        VARCHAR(64)  NOT NULL,
    is_enabled  BOOLEAN      NOT NULL DEFAULT FALSE,
    name        VARCHAR(64)  NOT NULL,
    description TEXT         NOT NULL,
    digest      TEXT         NOT NULL,
    source_url  TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_definitions_updated_at
    BEFORE UPDATE ON definitions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_definitions_type        ON definitions (type);
CREATE INDEX idx_definitions_is_enabled  ON definitions (is_enabled);
CREATE INDEX idx_definitions_name        ON definitions (name);
CREATE INDEX idx_definitions_description ON definitions USING GIN (to_tsvector('english', description));
