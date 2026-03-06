// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "module_type"))]
    pub struct ModuleType;
}

diesel::table! {
    definitions (id) {
        #[max_length = 64]
        id -> Varchar,
        #[sql_name = "type"]
        #[max_length = 64]
        type_ -> Varchar,
        is_enabled -> Bool,
        #[max_length = 64]
        name -> Varchar,
        description -> Text,
        digest -> Text,
        source_url -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ModuleType;

    modules (id) {
        #[max_length = 64]
        id -> Varchar,
        #[sql_name = "type"]
        type_ -> ModuleType,
        is_enabled -> Bool,
        #[max_length = 64]
        name -> Varchar,
        description -> Text,
        digest -> Text,
        source_url -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    routines (pid) {
        pid -> Uuid,
        name -> Text,
        description -> Text,
        environment -> Text,
        env_config -> Jsonb,
        priority -> Int2,
        timeout_ms -> Nullable<Int8>,
        retry_max_attempts -> Int2,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::allow_tables_to_appear_in_same_query!(definitions, modules, routines,);
