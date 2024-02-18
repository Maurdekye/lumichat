pub mod schema;

pub mod model {
    use diesel::{deserialize::Queryable, sql_types::SqlType};
    use serde::{Deserialize, Serialize};
    use chrono::NaiveDateTime;
    use diesel_derive_enum::DbEnum;

    #[derive(Queryable, Serialize, Deserialize, Clone, Debug)]
    pub struct FullUser {
        pub id: i32,
        pub username: String,
        pub email: String,
        pub password_hash: String,
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

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    pub struct User {
        pub id: i32,
        pub username: String,
        pub email: String,
        pub admin: bool,
    }

    #[derive(Queryable, Serialize, Deserialize, Clone, Debug, PartialEq)]
    pub struct Chat {
        pub id: i32,
        pub name: String,
        pub owner: i32,
        pub created: NaiveDateTime,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, SqlType, DbEnum)]
    #[ExistingTypePath = "crate::schema::sql_types::AuthorType"]
    pub enum AuthorType {
        Assistant,
        User,
    }

    #[derive(Queryable, Serialize, Deserialize, Clone, Debug, PartialEq)]
    pub struct Message {
        pub id: i32,
        pub chat_id: i32,
        pub author: AuthorType,
        pub content: String,
        pub created: NaiveDateTime,
    }

}

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
        Failure(FailureReason)
    }
}

pub mod me {
    use serde::{Deserialize, Serialize};

    use crate::model::User;

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub enum Response {
        Anonymous,
        User(User)
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
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Response {
        pub chat: Chat,
        pub messages: Vec<Message>,
    }
}

pub mod websocket {
    
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub enum Message {}
}