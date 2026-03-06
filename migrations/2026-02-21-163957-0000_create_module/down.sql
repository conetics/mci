DROP INDEX IF EXISTS idx_modules_description;
DROP INDEX IF EXISTS idx_modules_name;
DROP INDEX IF EXISTS idx_modules_is_enabled;
DROP INDEX IF EXISTS idx_modules_type;

DROP TABLE IF EXISTS modules;
DROP TYPE  IF EXISTS module_type;
