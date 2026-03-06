DROP INDEX IF EXISTS idx_routines_updated_at;
DROP INDEX IF EXISTS idx_routines_created_at;
DROP INDEX IF EXISTS idx_routines_priority;
DROP INDEX IF EXISTS idx_routines_environment;
DROP INDEX IF EXISTS idx_routines_description;
DROP INDEX IF EXISTS idx_routines_name;

DROP TRIGGER IF EXISTS trg_routines_updated_at ON routines;
DROP TABLE IF EXISTS routines;
