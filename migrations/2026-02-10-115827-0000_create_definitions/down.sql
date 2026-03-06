DROP INDEX IF EXISTS idx_definitions_description;
DROP INDEX IF EXISTS idx_definitions_name;
DROP INDEX IF EXISTS idx_definitions_is_enabled;
DROP INDEX IF EXISTS idx_definitions_type;

DROP TRIGGER IF EXISTS update_definitions_updated_at ON definitions;
DROP TABLE IF EXISTS definitions;
