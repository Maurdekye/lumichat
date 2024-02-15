pub mod model {
    use diesel::deserialize::Queryable;
    use serde::{Deserialize, Serialize};

    #[derive(Queryable, Serialize, Deserialize, Clone, Debug)]
    pub struct User {
        pub id: i32,
        pub username: String,
        pub email: String,
        pub password_hash: String,
    }
}

pub mod login {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Request {
        pub identifier: String,
        pub password: String,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Response {
        pub success: bool,
        pub message: String,
    }
}

pub mod me {
    use serde::{Deserialize, Serialize};

    use crate::model::User;

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub enum UserIdentity {
        Anonymous,
        User,
    }
    
    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Response {
        pub identity: UserIdentity,
        pub user: Option<User>,
    }
}

pub mod signup {
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
    pub enum ResponseType {
        InvalidPassword(PasswordValidationError),
        UserExists,
        Success(User),
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Response {
        pub success: bool,
        pub result: ResponseType,
    }
}