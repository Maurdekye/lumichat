pub mod schema;

pub mod model {
    use chrono::NaiveDateTime;
    use diesel::prelude::*;
    use diesel::SqlType;
    use diesel_derive_enum::DbEnum;
    use serde::{Deserialize, Serialize};

    pub type UserId = i32;

    #[derive(Queryable, Identifiable, Serialize, Deserialize, Clone, Debug)]
    #[diesel(table_name = crate::schema::users)]
    #[diesel(check_for_backend(diesel::pg::Pg))]
    pub struct FullUser {
        pub id: UserId,
        pub username: String,
        pub email: String,
        pub password_hash: String,
        pub admin: bool,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    pub struct User {
        pub id: UserId,
        pub username: String,
        pub email: String,
        pub admin: bool,
    }

    impl From<FullUser> for User {
        fn from(
            FullUser {
                id,
                username,
                email,
                admin,
                ..
            }: FullUser,
        ) -> Self {
            User {
                id,
                username,
                email,
                admin,
            }
        }
    }

    pub type ChatId = i32;

    #[derive(
        Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, Debug, PartialEq,
    )]
    #[diesel(table_name = crate::schema::chats)]
    #[diesel(check_for_backend(diesel::pg::Pg))]
    pub struct Chat {
        pub id: ChatId,
        pub name: String,
        pub owner: UserId,
        pub created: NaiveDateTime,
        pub model: String,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, SqlType, DbEnum)]
    #[ExistingTypePath = "crate::schema::sql_types::AuthorType"]
    pub enum AuthorType {
        User,
        AssistantResponding,
        AssistantFinished,
        AssistantError,
    }

    pub type MessageId = i32;

    #[derive(Queryable, Identifiable, Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[diesel(table_name = crate::schema::messages)]
    #[diesel(check_for_backend(diesel::pg::Pg))]
    pub struct Message {
        pub id: MessageId,
        pub chat: ChatId,
        pub author: AuthorType,
        pub content: String,
        pub error: Option<String>,
        pub created: NaiveDateTime,
    }

    #[derive(Queryable, Selectable, AsChangeset, Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[diesel(table_name = crate::schema::modelsettings)]
    #[diesel(check_for_backend(diesel::pg::Pg))]
    pub struct ModelSettings {
        pub temperature: f64,
        pub context_length: i32,
        pub system_prompt: Option<String>,
    }

    impl Default for ModelSettings {
        fn default() -> Self {
            Self {
                temperature: 0.8,
                context_length: 4096,
                system_prompt: None,
            }
        }
    }
}

pub mod api {
    pub mod login {
        use serde::{Deserialize, Serialize};

        use crate::model::User;

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Request {
            pub identifier: String,
            pub password: String,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum FailureReason {
            AlreadyLoggedIn,
            UserDoesNotExist,
            InvalidPassword,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Response {
            Success(User),
            Failure(FailureReason),
        }
    }

    pub mod me {
        use serde::{Deserialize, Serialize};

        use crate::model::User;

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Response {
            Anonymous,
            User(User),
        }
    }

    pub mod create_user {
        use serde::{Deserialize, Serialize};

        use crate::model::User;

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Request {
            pub username: String,
            pub email: String,
            pub password: String,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum PasswordValidationError {}

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum FailureReason {
            InvalidPassword(PasswordValidationError),
            UserExists,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Response {
            Success(User),
            Failure(FailureReason),
        }
    }

    pub mod new_chat {
        use serde::{Deserialize, Serialize};

        use crate::model::{Chat, Message};

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Request {
            pub initial_message: String,
            pub model: String,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Response {
            pub chat: Chat,
            pub user_message: Message,
            pub assistant_response: Message,
        }
    }

    pub mod chat_message {
        use serde::{Deserialize, Serialize};

        use crate::model::{ChatId, Message};

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Request {
            pub chat: ChatId,
            pub message: String,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum FailureReason {
            ChatDoesNotExist,
            ChatNotOwnedByUser,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Response {
            Success {
                user_message: Message,
                assistant_response: Message,
            },
            Failure(FailureReason),
        }
    }

    pub mod update_chat {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum FailureReason {
            ChatDoesNotExist,
            ChatNotOwnedByUser,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Response {
            Success,
            Failure(FailureReason),
        }
    }

    pub mod list_chats {
        use serde::{Deserialize, Serialize};

        use crate::model::Chat;

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Response {
            pub chats: Vec<Chat>,
        }
    }

    pub mod check_chat {
        use chrono::NaiveDateTime;
        use serde::{Deserialize, Serialize};

        use crate::model::ChatId;

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Request {
            pub chat: ChatId,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum FailureReason {
            ChatDoesNotExist,
            ChatNotOwnedByUser,
            ChatHasNoMessages,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Response {
            Success {
                most_recent_message_created: NaiveDateTime,
            },
            Failure(FailureReason),
        }
    }

    pub mod list_messages {
        use serde::{Deserialize, Serialize};

        use crate::model::{ChatId, Message};

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Request {
            pub chat: ChatId,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum FailureReason {
            ChatDoesNotExist,
            ChatNotOwnedByUser,
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Response {
            Success { messages: Vec<Message> },
            Failure(FailureReason),
        }
    }

    pub mod list_models {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub struct Response {
            pub list: Vec<String>,
            pub default: String,
        }
    }

    pub mod model_settings {

        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum SettingsType {
            Default,
            Model(String),
        }

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Scope {
            My(SettingsType),
            Global(SettingsType),
        }

        pub mod get {
            pub type Request = super::Scope;

            pub type Response = crate::model::ModelSettings;
        }

        pub mod set {
            use serde::{Deserialize, Serialize};

            #[derive(Serialize, Deserialize, Clone, Debug)]
            pub struct Request {
                pub scope: super::Scope,
                pub settings: crate::model::ModelSettings,
            }

            pub type Response = ();
        }

        pub mod clear {
            pub type Request = super::Scope;

            pub type Response = ();
        }
    }
}

pub mod websocket {

    use serde::{Deserialize, Serialize};

    use crate::model::{ChatId, MessageId};

    pub mod chat {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Clone, Debug)]
        pub enum Message {
            Token(String),
            Error(String),
            Finish,
        }
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub enum Message {
        Message {
            chat: ChatId,
            message: MessageId,
            content: chat::Message,
        },
    }
}
