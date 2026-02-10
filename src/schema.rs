// @generated automatically by Diesel CLI.

diesel::table! {
    definitions (id) {
        #[max_length = 64]
        id -> Varchar,
        #[max_length = 64]
        definition_type -> Varchar,
        enabled -> Bool,
        definition_url -> Text,
        source_url -> Text,
        #[max_length = 500]
        description -> Varchar,
    }
}
