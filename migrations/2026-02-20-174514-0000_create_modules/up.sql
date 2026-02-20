CREATE TYPE module_type AS ENUM ('language', 'sandbox', 'interceptor', 'proxy', 'hook');

CREATE TABLE modules (
    id VARCHAR(64) PRIMARY KEY NOT NULL,
    type module_type NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    name VARCHAR(64) NOT NULL,
    description VARCHAR(500) NOT NULL,
    module_object_key TEXT NOT NULL,
    configuration_object_key TEXT NOT NULL,
    secrets_object_key TEXT NOT NULL,
    digest TEXT NOT NULL,
    source_url TEXT
);

CREATE INDEX idx_modules_type ON modules(type);
CREATE INDEX idx_modules_is_enabled ON modules(is_enabled);
CREATE INDEX idx_modules_name ON modules(name);
CREATE INDEX idx_modules_description ON modules(description);
