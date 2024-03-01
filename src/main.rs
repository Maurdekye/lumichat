use std::collections::HashMap;
use std::default::Default;
use std::env;
use std::sync::{Arc, RwLock};

use actix::{Actor, Addr, StreamHandler};
use actix_files as fs;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::RedisSessionStore, SessionMiddleware};
use actix_web::body::BoxBody;
use actix_web::cookie::Key;
use actix_web::web::Data;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws::{self};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};

use serde::Serialize;
use shared::{api::*, model::*, websocket};

use shared::schema::users::dsl as users_dsl;

mod ollama {
    use std::error::Error;

    use chrono::NaiveDateTime;
    use serde::{Deserialize, Deserializer};
    use serde_json::{Number, Value};

    fn ollama_datetime_deserializer<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::String(value) = Value::deserialize(deserializer)? else {
            return Err(serde::de::Error::custom("Expected date string"));
        };
        ollama_to_datetime(&value).map_err(serde::de::Error::custom)
    }

    fn ollama_to_datetime(datestr: &str) -> Result<NaiveDateTime, impl Error> {
        NaiveDateTime::parse_from_str(&datestr, "%Y-%m-%dT%H:%M:%S%.fZ")
    }

    fn u64_from_number<E: serde::de::Error>(num: Number) -> Result<u64, E> {
        match num.as_u64() {
            Some(num) => Ok(num),
            None => Err(E::custom("expected a non null number")),
        }
    }

    fn u64_from_value<E: serde::de::Error>(value: Value) -> Result<u64, E> {
        let num = match value {
            Value::Number(token) => token,
            _ => return Err(E::custom("expected a number")),
        };
        u64_from_number(num)
    }

    macro_rules! from_map {
        ($map:expr, $key:literal, $typ:path) => {
            if let Some($typ(inner)) = $map.remove($key) {
                Ok(inner)
            } else {
                Err(serde::de::Error::missing_field($key))
            }
        };
    }

    pub mod chat {
        use super::{ollama_to_datetime, u64_from_number};
        use chrono::NaiveDateTime;
        use serde::{Deserialize, Serialize};
        use serde_json::Value;

        #[derive(Serialize, Deserialize)]
        pub enum Role {
            #[serde(rename = "system")]
            System,
            #[serde(rename = "user")]
            User,
            #[serde(rename = "assistant")]
            Assistant,
        }

        impl From<shared::model::AuthorType> for Role {
            fn from(value: shared::model::AuthorType) -> Self {
                match value {
                    shared::model::AuthorType::User => Role::User,
                    _ => Role::Assistant,
                }
            }
        }

        #[derive(Serialize, Deserialize)]
        pub struct Message {
            pub role: Role,
            pub content: String,
        }

        impl From<shared::model::Message> for Message {
            fn from(value: shared::model::Message) -> Self {
                Self {
                    role: value.author.into(),
                    content: value.content,
                }
            }
        }

        pub enum NumPredict {
            Tokens(u32),
            #[allow(unused)]
            Infinite,
            #[allow(unused)]
            FillContext,
        }

        impl Serialize for NumPredict {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let int_val = match &self {
                    NumPredict::Tokens(n) => *n as i32,
                    NumPredict::Infinite => -1,
                    NumPredict::FillContext => -2,
                };
                serializer.serialize_i32(int_val)
            }
        }

        #[derive(Serialize)]
        pub struct Options {
            pub temperature: f64,
            pub num_predict: NumPredict,
        }

        #[derive(Serialize)]
        pub struct Request {
            pub model: String,
            pub messages: Vec<Message>,
            pub options: Options,
        }

        pub enum Response {
            Error {
                error: String,
            },
            Progress {
                model: String,
                created_at: NaiveDateTime,
                message: Message,
            },
            Finish {
                model: String,
                created_at: NaiveDateTime,
                total_duration: u64,
                load_duration: u64,
                // prompt_eval_count: u64,
                prompt_eval_duration: u64,
                eval_count: u64,
                eval_duration: u64,
            },
        }

        impl<'de> Deserialize<'de> for Response {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = Value::deserialize(deserializer)?;
                let Value::Object(mut map) = value else {
                    return Err(serde::de::Error::custom("Expected a JSON object"));
                };

                if let Some(Value::String(error)) = map.remove("error") {
                    return Ok(Response::Error { error });
                }

                let model = from_map!(map, "model", Value::String)?;
                let created_at = ollama_to_datetime(&from_map!(map, "created_at", Value::String)?)
                    .map_err(serde::de::Error::custom)?;
                let done = from_map!(map, "done", Value::Bool)?;

                if done {
                    let total_duration =
                        u64_from_number(from_map!(map, "total_duration", Value::Number)?)?;
                    let load_duration =
                        u64_from_number(from_map!(map, "load_duration", Value::Number)?)?;
                    // let prompt_eval_count =
                    //     u64_from_number(from_map!(map, "prompt_eval_count", Value::Number)?)?;
                    let prompt_eval_duration =
                        u64_from_number(from_map!(map, "prompt_eval_duration", Value::Number)?)?;
                    let eval_count = u64_from_number(from_map!(map, "eval_count", Value::Number)?)?;
                    let eval_duration =
                        u64_from_number(from_map!(map, "eval_duration", Value::Number)?)?;
                    Ok(Response::Finish {
                        model,
                        created_at,
                        total_duration,
                        load_duration,
                        // prompt_eval_count,
                        prompt_eval_duration,
                        eval_count,
                        eval_duration,
                    })
                } else {
                    let Some(message) = map.remove("message") else {
                        return Err(serde::de::Error::missing_field("message"));
                    };
                    let message: Message =
                        serde_json::from_value(message).map_err(serde::de::Error::custom)?;
                    Ok(Response::Progress {
                        model,
                        created_at,
                        message,
                    })
                }
            }
        }
    }

    // deprecated by move to chat api
    #[allow(unused)]
    pub mod generate {
        use chrono::NaiveDateTime;
        use serde::{Deserialize, Serialize};
        use serde_json::{Number, Value};

        use super::{ollama_to_datetime, u64_from_number, u64_from_value};

        #[derive(Serialize)]
        pub struct Request {
            pub model: String,
            pub prompt: String,
            pub context: Option<Vec<u32>>,
        }

        #[derive(Debug)]
        pub enum Response {
            Error {
                error: String,
            },
            Progress {
                model: String,
                created_at: NaiveDateTime,
                response: String,
            },
            Finish {
                model: String,
                created_at: NaiveDateTime,
                context: Vec<u64>,
                total_duration: u64,
                load_duration: u64,
                prompt_eval_count: u64,
                prompt_eval_duration: u64,
                eval_count: u64,
                eval_duration: u64,
            },
        }

        impl<'de> Deserialize<'de> for Response {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = Value::deserialize(deserializer)?;
                let Value::Object(mut map) = value else {
                    return Err(serde::de::Error::custom("Expected a JSON object"));
                };

                if let Some(Value::String(error)) = map.remove("error") {
                    return Ok(Response::Error { error });
                }

                let model = from_map!(map, "model", Value::String)?;
                let created_at = ollama_to_datetime(&from_map!(map, "created_at", Value::String)?)
                    .map_err(serde::de::Error::custom)?;
                let done = from_map!(map, "done", Value::Bool)?;

                if done {
                    let context = from_map!(map, "context", Value::Array)?
                        .into_iter()
                        .map(u64_from_value)
                        .collect::<Result<Vec<_>, _>>()?;
                    let total_duration =
                        u64_from_number(from_map!(map, "total_duration", Value::Number)?)?;
                    let load_duration =
                        u64_from_number(from_map!(map, "load_duration", Value::Number)?)?;
                    let prompt_eval_count =
                        u64_from_number(from_map!(map, "prompt_eval_count", Value::Number)?)?;
                    let prompt_eval_duration =
                        u64_from_number(from_map!(map, "prompt_eval_duration", Value::Number)?)?;
                    let eval_count = u64_from_number(from_map!(map, "eval_count", Value::Number)?)?;
                    let eval_duration =
                        u64_from_number(from_map!(map, "eval_duration", Value::Number)?)?;
                    Ok(Response::Finish {
                        model,
                        created_at,
                        context,
                        total_duration,
                        load_duration,
                        prompt_eval_count,
                        prompt_eval_duration,
                        eval_count,
                        eval_duration,
                    })
                } else {
                    let response = from_map!(map, "response", Value::String)?;
                    Ok(Response::Progress {
                        model,
                        created_at,
                        response,
                    })
                }
            }
        }
    }

    pub mod tags {
        use chrono::NaiveDateTime;
        use serde::Deserialize;

        use super::ollama_datetime_deserializer;

        #[derive(Deserialize)]
        pub struct Response {
            pub models: Vec<ModelInfo>,
        }

        #[derive(Deserialize)]
        pub struct ModelInfo {
            pub name: String,
            #[serde(deserialize_with = "ollama_datetime_deserializer")]
            pub modified_at: NaiveDateTime,
            pub size: u64,
            pub digest: String,
            pub details: ModelDetails,
        }

        #[derive(Deserialize)]
        pub struct ModelDetails {
            pub format: String,
            pub family: String,
            pub families: Option<Vec<String>>,
            pub parameter_size: String,
            pub quantization_level: String,
        }
    }
}

mod settings {
    use diesel::prelude::*;
    use diesel::{delete, insert_into};
    use shared::model::ModelSettings;
    use shared::model::UserId;
    use shared::schema::modelsettings;

    use crate::DatabaseConnection;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Scope {
        Default,
        Global,
        Model(String),
        User(UserId),
        UserDefaultWithModel(UserId, String),
        UserModel(UserId, String),
    }

    impl Scope {
        fn up(self) -> Self {
            match self {
                Scope::Default => unimplemented!("Nothing above default scope"),
                Scope::Global => Scope::Default,
                Scope::Model(_) => Scope::Global,
                Scope::User(_) => Scope::Global,
                Scope::UserDefaultWithModel(_, model) => Scope::Model(model),
                Scope::UserModel(user_id, model) => Scope::UserDefaultWithModel(user_id, model),
            }
        }

        fn key(&self) -> String {
            match self {
                Scope::Default => unimplemented!("Default scope is never stored"),
                Scope::Global => format!("GLOBAL"),
                Scope::Model(model) => format!("MODEL#{model}"),
                Scope::User(user_id) | Scope::UserDefaultWithModel(user_id, _) => {
                    format!("USER#{user_id}")
                }
                Scope::UserModel(user_id, model) => format!("USER#{user_id}#MODEL#{model}"),
            }
        }
    }

    pub fn get(db: &mut DatabaseConnection, mut scope: Scope) -> ModelSettings {
        while scope != Scope::Default {
            let value: Option<ModelSettings> = modelsettings::dsl::modelsettings
                .select(ModelSettings::as_select())
                .filter(modelsettings::dsl::scope.eq(scope.key()))
                .first(db)
                .optional()
                .expect("Unable to query database");
            if let Some(value) = value {
                return value;
            }
            scope = scope.up();
        }
        ModelSettings::default()
    }

    #[derive(Identifiable, Insertable, AsChangeset)]
    #[diesel(table_name = shared::schema::modelsettings)]
    #[diesel(primary_key(scope))]
    struct NewModelSettings {
        scope: String,
        temperature: f64,
        context_length: i32,
        system_prompt: Option<String>,
    }

    impl NewModelSettings {
        fn from(
            scope: Scope,
            ModelSettings {
                temperature,
                context_length,
                system_prompt,
            }: ModelSettings,
        ) -> Self {
            Self {
                scope: scope.key(),
                temperature,
                context_length,
                system_prompt,
            }
        }
    }

    pub fn set(db: &mut DatabaseConnection, scope: Scope, settings: ModelSettings) {
        let new_settings = NewModelSettings::from(scope, settings);
        insert_into(modelsettings::dsl::modelsettings)
            .values(&new_settings)
            .on_conflict(modelsettings::dsl::scope)
            .do_update()
            .set(&new_settings)
            .execute(db)
            .expect("Error updating database");
    }

    pub fn clear(db: &mut DatabaseConnection, scope: Scope) {
        delete(modelsettings::dsl::modelsettings.filter(modelsettings::dsl::scope.eq(scope.key())))
            .execute(db)
            .expect("Error updating database");
    }
}

type Database = r2d2::Pool<ConnectionManager<PgConnection>>;
type DatabaseConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

fn validate_password(_password: &str) -> Result<(), create_user::PasswordValidationError> {
    Ok(()) // no validation for now
}

enum Response<T> {
    Okay(T),
    BadRequest(T),
    Unauthorized,
}

use self::Response::*;

impl<T> Responder for Response<T>
where
    T: Serialize,
{
    type Body = BoxBody;

    fn respond_to(self, _: &HttpRequest) -> HttpResponse<Self::Body> {
        match self {
            Okay(payload) => HttpResponse::Ok().json(payload),
            BadRequest(payload) => HttpResponse::BadRequest().json(payload),
            Unauthorized => HttpResponse::Unauthorized().finish(),
        }
    }
}

macro_rules! response_try {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => return $crate::Response::BadRequest(error),
        }
    };
}

struct Websocket;

impl Actor for Websocket {
    type Context = ws::WebsocketContext<Self>;
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for Websocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Err(err) => eprintln!("ws error: {err}"),
            Ok(msg) => match msg {
                ws::Message::Ping(msg) => ctx.pong(&msg),
                ws::Message::Pong(_) => {}
                _ => {}
            },
        }
    }
}

#[derive(actix::Message)]
#[rtype(result = "()")]
struct WebsocketMessage(websocket::Message);

impl From<websocket::Message> for WebsocketMessage {
    fn from(value: websocket::Message) -> Self {
        Self(value)
    }
}

impl actix::Handler<WebsocketMessage> for Websocket {
    type Result = ();

    fn handle(&mut self, msg: WebsocketMessage, ctx: &mut Self::Context) {
        ctx.text(
            serde_json::to_string(&msg.0).expect("Websocket messages should be serializeable"),
        );
    }
}

#[derive(Clone)]
struct Config {
    admin_signup: bool,
    llm_api_url: String,
}

#[derive(Default)]
struct StateInner {
    websock_connections: HashMap<UserId, Vec<Addr<Websocket>>>,
}

impl StateInner {
    fn send_to_connections(connections: &mut Vec<Addr<Websocket>>, message: websocket::Message) {
        connections.retain(Addr::connected);
        for connection in connections.iter_mut() {
            connection.do_send(message.clone().into());
        }
    }

    pub fn send_message(&mut self, user_id: UserId, message: websocket::Message) {
        if let Some(connections) = self.websock_connections.get_mut(&user_id) {
            StateInner::send_to_connections(connections, message);
            if connections.is_empty() {
                self.websock_connections.remove(&user_id);
            }
        }
    }

    #[allow(unused)]
    pub fn broadcast_message(&mut self, message: websocket::Message) {
        for (_user_id, connections) in self.websock_connections.iter_mut() {
            StateInner::send_to_connections(connections, message.clone());
        }
        self.websock_connections.retain(|_, c| !c.is_empty());
    }
}

type State = Arc<RwLock<StateInner>>;

trait UserIdFromIdentity {
    fn user_id(&self) -> Option<UserId>;
}

impl UserIdFromIdentity for Identity {
    fn user_id(&self) -> Option<UserId> {
        self.id().ok()?.parse::<UserId>().ok()
    }
}

trait FullUserFromIdentity {
    fn user(&self, db: &mut DatabaseConnection) -> Option<FullUser>;
}

impl FullUserFromIdentity for Identity {
    fn user(&self, db: &mut DatabaseConnection) -> Option<FullUser> {
        let user_id = self.user_id()?;
        users_dsl::users
            .find(user_id)
            .first::<FullUser>(db)
            .optional()
            .ok()?
            .map(Into::into)
    }
}

impl FullUserFromIdentity for Option<Identity> {
    fn user(&self, db: &mut DatabaseConnection) -> Option<FullUser> {
        self.as_ref().and_then(|ident| ident.user(db))
    }
}

mod api {
    use std::error::Error;
    use std::iter::once;

    use actix_identity::Identity;
    use actix_web::web::{self, Data, Json};
    use actix_web::{get, post, HttpMessage, HttpRequest, HttpResponse, Responder};
    use actix_web_actors::ws::WsResponseBuilder;
    use bcrypt::{hash, verify, DEFAULT_COST};
    use chrono::{NaiveDateTime, Utc};
    use diesel::prelude::*;
    use diesel::Insertable;
    use diesel::{insert_into, update};
    use futures::stream::StreamExt;
    use reqwest::Client;

    use shared::{api::*, model::*, websocket};

    use shared::schema::{
        chats::dsl as chats_dsl, messages::dsl as messages_dsl, users::dsl as users_dsl,
    };

    use crate::{
        ollama, settings, validate_password, Config, Database, DatabaseConnection,
        FullUserFromIdentity,
        Response::{self, *},
        State, UserIdFromIdentity, Websocket,
    };

    // Websocket management

    // TODO: accept periodic pings & close dead connections that dont send them

    #[get("/ws")]
    pub async fn ws_handler(
        request: HttpRequest,
        stream: web::Payload,
        identity: Identity,
        state: Data<State>,
    ) -> impl Responder {
        println!("/ws");
        let user_id = identity.user_id().expect("Failed to get user id");
        let mut state = state.write().unwrap();
        let (websocket_address, response) = WsResponseBuilder::new(Websocket, &request, stream)
            .start_with_addr()
            .expect("Unable to create websocket connection");
        state
            .websock_connections
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(websocket_address);
        response
    }

    // User Authentication

    #[derive(Insertable)]
    #[diesel(table_name = shared::schema::users)]
    pub struct NewFullUser<'a> {
        username: &'a str,
        email: &'a str,
        password_hash: &'a str,
        admin: bool,
    }

    #[post("/admin-signup")]
    async fn admin_signup_handler(
        body: Json<create_user::Request>,
        db: Data<Database>,
        config: Data<Config>,
    ) -> Response<create_user::Response> {
        // check if admin signup is enabled
        if !config.admin_signup {
            return Unauthorized;
        }

        // proceed to user creation
        let mut db = db.get().expect("Database not available");
        create_user_inner(body, &mut db, true).await
    }

    #[post("/create-user")]
    async fn create_user_handler(
        identity: Identity,
        body: Json<create_user::Request>,
        db: Data<Database>,
    ) -> Response<create_user::Response> {
        // check if operating user is an admin
        let mut db = db.get().expect("Database not available");
        let user = identity.user(&mut db).expect("Unable to load user profile");
        if !user.admin {
            return Unauthorized;
        }

        // proceed to user creation
        create_user_inner(body, &mut db, false).await
    }

    async fn create_user_inner(
        body: Json<create_user::Request>,
        db: &mut DatabaseConnection,
        make_admin: bool,
    ) -> Response<create_user::Response> {
        // decode request
        let body = body.into_inner();
        println!("/create-user: {body:#?}");

        // validate password
        response_try!(validate_password(&body.password)
            .map_err(create_user::FailureReason::InvalidPassword)
            .map_err(create_user::Response::Failure));

        // check for existing users
        let user_query = users_dsl::users
            .filter(users_dsl::username.eq(&body.username))
            .or_filter(users_dsl::email.eq(&body.email))
            .first::<FullUser>(db)
            .optional()
            .expect("Error querying database");

        if let Some(_) = user_query {
            return BadRequest(create_user::Response::Failure(
                create_user::FailureReason::UserExists,
            ));
        }

        // Prepare the new user data
        let new_user = NewFullUser {
            username: &body.username,
            email: &body.email,
            password_hash: &hash(&body.password, DEFAULT_COST).expect("Error hashing password"),
            admin: make_admin,
        };

        // Insert new user into the database
        let new_user: FullUser = insert_into(users_dsl::users)
            .values(&new_user)
            .get_result(db)
            .expect("Error inserting new user");

        // Respond successfully
        Okay(create_user::Response::Success(new_user.into()))
    }

    #[post("/login")]
    async fn login_handler(
        user: Option<Identity>,
        request: HttpRequest,
        body: Json<login::Request>,
        db: Data<Database>,
    ) -> Response<login::Response> {
        // check if already logged in
        if user.is_some() {
            return BadRequest(login::Response::Failure(
                login::FailureReason::AlreadyLoggedIn,
            ));
        }

        // decode request
        let body = body.into_inner();
        println!("/login: {body:#?}");

        // check database for user
        let mut db = db.get().expect("Database not available");
        let user_query = users_dsl::users
            .filter(
                users_dsl::username
                    .eq(&body.identifier)
                    .or(users_dsl::email.eq(&body.identifier)),
            )
            .first::<FullUser>(&mut db)
            .optional()
            .expect("Error querying database");

        let Some(user) = user_query else {
            return BadRequest(login::Response::Failure(
                login::FailureReason::UserDoesNotExist,
            ));
        };

        // check password
        if !verify(&body.password, &user.password_hash).expect("Error decrypting password") {
            return BadRequest(login::Response::Failure(
                login::FailureReason::InvalidPassword,
            ));
        }

        // log user in
        Identity::login(&request.extensions(), user.id.to_string()).unwrap();
        Okay(login::Response::Success(user.into()))
    }

    #[get("/me")]
    async fn me_handler(identity: Option<Identity>, db: Data<Database>) -> Response<me::Response> {
        println!("/me");
        let mut db = db.get().expect("Database not available");
        let response = match identity.user(&mut db) {
            None => me::Response::Anonymous,
            Some(user) => me::Response::User(user.into()),
        };
        Okay(response)
    }

    #[post("/logout")]
    async fn logout_handler(user: Identity) -> impl Responder {
        println!("/logout");
        user.logout();
        HttpResponse::Ok().finish()
    }

    // Chatting

    #[derive(Insertable)]
    #[diesel(table_name = shared::schema::messages)]
    struct NewMessage<'a> {
        chat: ChatId,
        author: AuthorType,
        content: &'a str,
        created: NaiveDateTime,
    }

    async fn submit_chat_message(
        mut db: DatabaseConnection,
        user: UserId,
        chat: Chat,
        content: &str,
        state: Data<State>,
        config: Data<Config>,
    ) -> (Message, Message) {
        // put new message into database
        let now = Utc::now().naive_utc();
        let new_message = NewMessage {
            chat: chat.id,
            author: AuthorType::User,
            content,
            created: now,
        };
        let user_message: Message = insert_into(messages_dsl::messages)
            .values(&new_message)
            .get_result(&mut db)
            .expect("Error inserting message into new chat");

        // get prior message context for llm query
        let messages: Vec<Message> = messages_dsl::messages
            .filter(messages_dsl::chat.eq(chat.id))
            .order(messages_dsl::created.asc())
            .load(&mut db)
            .expect("Error querying database");

        // put empty assistant response into database
        let assistant_message = NewMessage {
            chat: chat.id,
            author: AuthorType::AssistantResponding,
            content: "",
            created: now,
        };
        let assistant_message: Message = insert_into(messages_dsl::messages)
            .values(&assistant_message)
            .get_result(&mut db)
            .expect("Error inserting assistant message into new chat");

        // query llm
        {
            let assistant_message = assistant_message.clone();

            // fetch settings
            let model = chat.model.clone();
            let model_settings =
                settings::get(&mut db, settings::Scope::UserModel(user, model.clone()));
            let options = ollama::chat::Options {
                temperature: model_settings.temperature,
                num_predict: ollama::chat::NumPredict::Tokens(model_settings.context_length as u32),
            };

            // prepend system prompt if present
            let messages = messages.into_iter().map(ollama::chat::Message::from);
            let messages = if let Some(system_prompt) = model_settings.system_prompt {
                once(ollama::chat::Message {
                    role: ollama::chat::Role::System,
                    content: system_prompt,
                })
                .chain(messages)
                .collect()
            } else {
                messages.collect()
            };
            actix::spawn(async move {
                if let Err(error) = async {
                    let message = assistant_message.id;

                    let client = Client::new();
                    let mut response = client
                        .post(format!("{}/api/chat", config.llm_api_url))
                        .json(&ollama::chat::Request {
                            model,
                            messages,
                            options,
                        })
                        .send()
                        .await?
                        .bytes_stream();

                    let mut response_message = String::new();

                    let created_at = 'message_loop: {
                        let message_id = message;
                        let mut is_first_token = true;
                        while let Some(bytes) = response.next().await {
                            let response: ollama::chat::Response = serde_json::from_slice(&bytes?)?;
                            // println!("message: {response:?}");
                            match response {
                                ollama::chat::Response::Error { error } => Err(error)?,
                                ollama::chat::Response::Progress { message, .. } => {
                                    let mut content = message.content;

                                    // remove prefixed space character if it appears
                                    if is_first_token && content.chars().next() == Some(' ') {
                                        content = content.split_off(1);
                                        is_first_token = false;
                                    }

                                    // append new tokens to response
                                    response_message.push_str(&content);

                                    state.write().unwrap().send_message(
                                        user,
                                        websocket::Message::Message {
                                            chat: chat.id,
                                            message: message_id,
                                            content: websocket::chat::Message::Token(content),
                                        },
                                    );
                                }
                                ollama::chat::Response::Finish { created_at, .. } => {
                                    break 'message_loop created_at;
                                }
                            }
                        }
                        return Err("Unexpected end of message stream".into());
                    };

                    // send completion message
                    state.write().unwrap().send_message(
                        user,
                        websocket::Message::Message {
                            chat: chat.id,
                            message,
                            content: websocket::chat::Message::Finish,
                        },
                    );

                    // push completed message to database
                    update(&assistant_message)
                        .set((
                            messages_dsl::created.eq(created_at),
                            messages_dsl::content.eq(response_message),
                            messages_dsl::author.eq(AuthorType::AssistantFinished),
                        ))
                        .execute(&mut db)
                        .expect("Error updating database");

                    Ok::<_, Box<dyn Error>>(())
                }
                .await
                {
                    eprintln!("Error requesting completion from llm api: {:#?}", error);

                    let error_text = format!("{error}");

                    // send error message
                    state.write().unwrap().send_message(
                        user,
                        websocket::Message::Message {
                            chat: chat.id,
                            message: assistant_message.id,
                            content: websocket::chat::Message::Error(error_text.clone()),
                        },
                    );

                    // push error message to database
                    update(&assistant_message)
                        .set((
                            messages_dsl::error.eq(error_text),
                            messages_dsl::author.eq(AuthorType::AssistantError),
                        ))
                        .execute(&mut db)
                        .expect("Error updating database");
                }
            });
        }

        (user_message, assistant_message)
    }

    #[derive(Insertable)]
    #[diesel(table_name = shared::schema::chats)]
    struct NewChat<'a> {
        name: &'a str,
        owner: UserId,
        created: NaiveDateTime,
        model: &'a str,
    }

    #[post("/new-chat")]
    async fn new_chat_handler(
        identity: Identity,
        db: Data<Database>,
        state: Data<State>,
        config: Data<Config>,
        body: Json<new_chat::Request>,
    ) -> Response<new_chat::Response> {
        // decode request
        let body = body.into_inner();
        println!("/new-chat: {body:#?}");

        // put new chat into database
        let user_id = identity.user_id().expect("Failed to get user id");
        let mut db = db.get().expect("Database not available");
        let now = Utc::now().naive_utc();
        let chat = NewChat {
            name: "New Chat",
            owner: user_id,
            created: now.clone(),
            model: &body.model,
        };
        let chat: Chat = insert_into(chats_dsl::chats)
            .values(&chat)
            .get_result(&mut db)
            .expect("Error insterting new chat");

        // place new chat message in database
        let (user_message, assistant_response) = submit_chat_message(
            db,
            user_id,
            chat.clone(),
            &body.initial_message,
            state,
            config,
        )
        .await;

        // send chat id and assistant message id back
        let chat = chat.into();
        Okay(new_chat::Response {
            chat,
            user_message,
            assistant_response,
        })
    }

    enum GetChatError {
        ChatDoesNotExist,
        ChatNotOwnedByUser,
    }

    macro_rules! get_chat_error_into {
        ($typ:ty) => {
            impl Into<$typ> for GetChatError {
                fn into(self) -> $typ {
                    match self {
                        Self::ChatDoesNotExist => <$typ>::ChatDoesNotExist,
                        Self::ChatNotOwnedByUser => <$typ>::ChatNotOwnedByUser,
                    }
                }
            }
        };
    }

    fn get_chat_by_user(
        identity: Identity,
        chat: ChatId,
        db: &mut DatabaseConnection,
    ) -> Result<Chat, GetChatError> {
        // get associated chat
        let Some(chat): Option<Chat> = chats_dsl::chats
            .find(chat)
            .first(db)
            .optional()
            .expect("Error querying database")
        else {
            return Err(GetChatError::ChatDoesNotExist);
        };

        // confirm that user owns the given chat
        let user_id = identity.user_id().expect("Failed to get user id");
        if chat.owner != user_id {
            return Err(GetChatError::ChatNotOwnedByUser);
        }

        Ok(chat)
    }

    get_chat_error_into!(chat_message::FailureReason);

    #[post("/chat-message")]
    async fn chat_message_handler(
        identity: Identity,
        db: Data<Database>,
        state: Data<State>,
        config: Data<Config>,
        body: Json<chat_message::Request>,
    ) -> Response<chat_message::Response> {
        // decode request
        let body = body.into_inner();
        println!("/chat-message: {body:#?}");

        // check database that chat exists
        let mut db = db.get().expect("Database not available");
        let chat = response_try!(get_chat_by_user(identity, body.chat, &mut db)
            .map_err(Into::into)
            .map_err(chat_message::Response::Failure));

        // place new chat message in database
        let (user_message, assistant_response) =
            submit_chat_message(db, chat.owner, chat, &body.message, state, config).await;

        // send newly created messages back
        Okay(chat_message::Response::Success {
            user_message,
            assistant_response,
        })
    }

    get_chat_error_into!(update_chat::FailureReason);

    #[post("/update-chat")]
    async fn update_chat_handler(
        identity: Identity,
        body: Json<Chat>,
        db: Data<Database>,
    ) -> Response<update_chat::Response> {
        // decode request
        let chat = body.into_inner();
        println!("/update-chat: {chat:#?}");

        // check to make sure chat is valid
        let mut db = db.get().expect("Database not available");
        response_try!(get_chat_by_user(identity, chat.id, &mut db)
            .map_err(Into::into)
            .map_err(update_chat::Response::Failure));

        // perform update
        update(&chat)
            .set(&chat)
            .execute(&mut db)
            .expect("Error updating database");

        Okay(update_chat::Response::Success)
    }

    #[get("/list-chats")]
    async fn list_chats_handler(identity: Identity, db: Data<Database>) -> impl Responder {
        println!("/list-chats");

        // get chats owned by user
        let user_id = identity.user_id().expect("Failed to get user id");
        let mut db = db.get().expect("Database not available");
        let chats: Vec<Chat> = chats_dsl::chats
            .filter(chats_dsl::owner.eq(user_id))
            .load(&mut db)
            .expect("Error querying database");
        let chats = chats.into_iter().map(Chat::from).collect();

        HttpResponse::Ok().json(list_chats::Response { chats })
    }

    get_chat_error_into!(check_chat::FailureReason);

    #[post("/check-chat")]
    async fn check_chat_handler(
        identity: Identity,
        body: Json<check_chat::Request>,
        db: Data<Database>,
    ) -> Response<check_chat::Response> {
        // decode response
        let body = body.into_inner();
        println!("/check-chat: {body:#?}");

        // get associated chat
        let mut db = db.get().expect("Database not available");
        let chat = response_try!(get_chat_by_user(identity, body.chat, &mut db)
            .map_err(Into::into)
            .map_err(check_chat::Response::Failure));

        // get most recent message timestamp
        let Some(most_recent_message): Option<Message> = messages_dsl::messages
            .filter(messages_dsl::chat.eq(chat.id))
            .order(messages_dsl::created.desc())
            .first(&mut db)
            .optional()
            .expect("Error querying database")
        else {
            return BadRequest(check_chat::Response::Failure(
                check_chat::FailureReason::ChatHasNoMessages,
            ));
        };

        // respond with message time
        Okay(check_chat::Response::Success {
            most_recent_message_created: most_recent_message.created,
        })
    }

    get_chat_error_into!(list_messages::FailureReason);

    #[post("/list-messages")]
    async fn list_messages_handler(
        identity: Identity,
        body: Json<list_messages::Request>,
        db: Data<Database>,
    ) -> Response<list_messages::Response> {
        // decode response
        let body = body.into_inner();
        println!("/list-messages: {body:#?}");

        // get associated chat
        let mut db = db.get().expect("Database not available");
        let chat = response_try!(get_chat_by_user(identity, body.chat, &mut db)
            .map_err(Into::into)
            .map_err(list_messages::Response::Failure));

        // get messages
        let messages = messages_dsl::messages
            .filter(messages_dsl::chat.eq(chat.id))
            .order(messages_dsl::created.asc())
            .load(&mut db)
            .expect("Error querying database");

        // TODO: fetch in progress messages to deliver to the user as well

        Okay(list_messages::Response::Success { messages })
    }

    #[get("/list-models")]
    async fn list_models_handler(config: Data<Config>) -> Response<list_models::Response> {
        println!("/list-models");
        // fetch list of models

        let client = Client::new();
        let response = client
            .get(format!("{}/api/tags", config.llm_api_url))
            .send()
            .await
            .expect("Error communicating with llm api")
            .bytes()
            .await
            .expect("Error collecting response from llm api");

        let response: ollama::tags::Response =
            serde_json::from_slice(&response).expect("Error deserializing llm api response");

        let list: Vec<String> = response.models.into_iter().map(|m| m.name).collect();
        let default = list.first().cloned().unwrap_or_default();
        Okay(list_models::Response { list, default })
    }

    #[post("/model-settings/get")]
    async fn model_settings_get_handler(
        identity: Identity,
        db: Data<Database>,
        body: Json<model_settings::get::Request>,
    ) -> Response<model_settings::get::Response> {
        use model_settings::Scope as RequestScope;
        use model_settings::SettingsType;
        use settings::Scope;

        // decode response
        let body = body.into_inner();
        println!("/model-settings/get: {body:#?}");

        // get user
        let mut db = db.get().expect("Error connecting to database");
        let user = identity.user(&mut db).expect("Error fetching user");

        // determine scope of request
        let scope = match body {
            RequestScope::Global(SettingsType::Default) => Scope::Global,
            RequestScope::Global(SettingsType::Model(model)) => Scope::Model(model),
            RequestScope::My(SettingsType::Default) => Scope::User(user.id),
            RequestScope::My(SettingsType::Model(model)) => Scope::UserModel(user.id, model),
        };

        // retrieve settings
        let settings = settings::get(&mut db, scope);

        Okay(settings)
    }

    #[post("/model-settings/set")]
    async fn model_settings_set_handler(
        identity: Identity,
        db: Data<Database>,
        body: Json<model_settings::set::Request>,
    ) -> Response<model_settings::set::Response> {
        use model_settings::Scope as RequestScope;
        use model_settings::SettingsType;
        use settings::Scope;

        // decode response
        let body = body.into_inner();
        println!("/model-settings/set: {body:#?}");

        // get user
        let mut db = db.get().expect("Error connecting to database");
        let user = identity.user(&mut db).expect("Error fetching user");

        // determine if user is allowed to set global settings
        if let RequestScope::Global(_) = body.scope {
            if !user.admin {
                return Unauthorized;
            }
        }

        // determine scope of request
        let scope = match body.scope {
            RequestScope::Global(SettingsType::Default) => Scope::Global,
            RequestScope::Global(SettingsType::Model(model)) => Scope::Model(model),
            RequestScope::My(SettingsType::Default) => Scope::User(user.id),
            RequestScope::My(SettingsType::Model(model)) => Scope::UserModel(user.id, model),
        };

        // perform update
        settings::set(&mut db, scope, body.settings);

        Okay(())
    }

    #[post("/model-settings/clear")]
    async fn model_settings_clear_handler(
        identity: Identity,
        db: Data<Database>,
        body: Json<model_settings::clear::Request>,
    ) -> Response<model_settings::clear::Response> {
        use model_settings::Scope as RequestScope;
        use model_settings::SettingsType;
        use settings::Scope;

        // decode response
        let body = body.into_inner();
        println!("/model-settings/clear: {body:#?}");

        // get user
        let mut db = db.get().expect("Error connecting to database");
        let user = identity.user(&mut db).expect("Error fetching user");

        // determine if user is allowed to clear global settings
        if let RequestScope::Global(_) = body {
            if !user.admin {
                return Unauthorized;
            }
        }

        // determine scope of request
        let scope = match body {
            RequestScope::Global(SettingsType::Default) => Scope::Global,
            RequestScope::Global(SettingsType::Model(model)) => Scope::Model(model),
            RequestScope::My(SettingsType::Default) => Scope::User(user.id),
            RequestScope::My(SettingsType::Model(model)) => Scope::UserModel(user.id, model),
        };

        // perform update
        settings::clear(&mut db, scope);

        Okay(())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting");

    // read env vars
    let identity_secret = env::var("IDENTITY_SECRET").expect("IDENTITY_SECRET must be set");
    let port = env::var("PORT").expect("PORT must be set");
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url = env::var("REDIS_URL").unwrap_or("redis://127.0.0.1:6379".to_string());
    let llm_api_url = env::var("LLM_API_URL").expect("LLM_API_URL must be set");
    let admin_signup = env::var("ADMIN_SIGNUP").map(|val| val.trim().to_ascii_uppercase())
        == Ok("TRUE".to_string());
    let host_addr = format!("0.0.0.0:{}", port);

    println!("port: {port}");
    println!("database_url: {database_url}");
    println!("redis_url: {redis_url}");
    println!("llm_api_url: {llm_api_url}");
    println!("admin_signup: {admin_signup}");

    // connect to db
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool: Database = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    println!("Connected to database");

    // connect to redis
    let redis = RedisSessionStore::new(redis_url).await.unwrap();
    println!("Connected to redis");

    // initialize app state & config
    let state = State::default();
    let config = Config {
        admin_signup,
        llm_api_url,
    };

    // serve app
    println!("Running on {}", host_addr);
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .app_data(Data::new(state.clone()))
            .app_data(Data::new(config.clone()))
            .wrap(IdentityMiddleware::default())
            .wrap(SessionMiddleware::new(
                redis.clone(),
                Key::from(identity_secret.as_bytes()),
            ))
            .service(api::ws_handler)
            .service(api::admin_signup_handler)
            .service(api::create_user_handler)
            .service(api::login_handler)
            .service(api::logout_handler)
            .service(api::me_handler)
            .service(api::new_chat_handler)
            .service(api::chat_message_handler)
            .service(api::update_chat_handler)
            .service(api::list_chats_handler)
            .service(api::check_chat_handler)
            .service(api::list_messages_handler)
            .service(api::list_models_handler)
            .service(api::model_settings_get_handler)
            .service(api::model_settings_set_handler)
            .service(api::model_settings_clear_handler)
            .service(fs::Files::new("/", "./front/dist").index_file("index.html"))
    })
    .workers(
        std::thread::available_parallelism()
            .map(Into::into)
            .unwrap_or(1),
    )
    .bind(host_addr)?
    .run()
    .await
}
