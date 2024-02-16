pub mod model {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    pub struct User {
        pub id: i32,
        pub username: String,
        pub email: String,
        pub admin: bool,
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
