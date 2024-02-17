// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "author_type"))]
    pub struct AuthorType;
}

diesel::table! {
    chats (id) {
        id -> Int4,
        #[max_length = 255]
        name -> Varchar,
        owner -> Int4,
        created -> Timestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::AuthorType;

    messages (id) {
        id -> Int4,
        chat_id -> Int4,
        author -> AuthorType,
        content -> Text,
        created -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        username -> Varchar,
        email -> Varchar,
        password_hash -> Varchar,
        admin -> Bool,
    }
}

diesel::joinable!(chats -> users (owner));
diesel::joinable!(messages -> chats (chat_id));

diesel::allow_tables_to_appear_in_same_query!(
    chats,
    messages,
    users,
);
