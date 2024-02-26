use std::collections::HashMap;
use std::convert::identity;
use std::default::Default;
use std::env;
use std::error::Error;
use std::sync::{Arc, RwLock};

use actix::{Actor, Addr, StreamHandler};
use actix_files as fs;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::RedisSessionStore, SessionMiddleware};
use actix_web::body::BoxBody;
use actix_web::cookie::Key;
use actix_web::web::{self, Data, Json};
use actix_web::{get, post, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws::{self, WsResponseBuilder};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::Insertable;
use diesel::{insert_into, update};
use futures::stream::StreamExt;
use reqwest::Client;

use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use shared::{api::*, model::*, websocket};

use shared::schema::{
    chats::dsl as chats_dsl, messages::dsl as messages_dsl, users::dsl as users_dsl,
};

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
    pub fn send_message(&mut self, user_id: UserId, message: websocket::Message) {
        if let Some(connections) = self.websock_connections.get_mut(&user_id) {
            connections.retain(Addr::connected);
            for connection in connections.iter_mut() {
                connection.do_send(message.clone().into());
            }
            if connections.is_empty() {
                self.websock_connections.remove(&user_id);
            }
        }
    }

    #[allow(unused)]
    pub fn broadcast_message(&mut self, message: websocket::Message) {
        for (_user_id, connections) in self.websock_connections.iter_mut() {
            connections.retain(Addr::connected);
            for connection in connections {
                connection.do_send(message.clone().into())
            }
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

// Websocket management

// TODO: accept periodic pings & close dead connections that dont send them

#[get("/ws")]
async fn ws_handler(
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
    if let Err(validation_error) = validate_password(&body.password) {
        return BadRequest(create_user::Response::Failure(
            create_user::FailureReason::InvalidPassword(validation_error),
        ));
    }

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

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    context: Option<Vec<u32>>,
}

#[allow(unused)]
#[derive(Debug)]
enum OllamaResponse {
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
        context: Vec<u32>,
        total_duration: u32,
        load_duration: u32,
        prompt_eval_count: u32,
        prompt_eval_duration: u32,
        eval_count: u32,
        eval_duration: u32,
    },
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

impl<'de> Deserialize<'de> for OllamaResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        fn u32_from_number<E: serde::de::Error>(num: Number) -> Result<u32, E> {
            match num.as_u64() {
                Some(num) => Ok(num as u32),
                None => Err(E::custom("expected a non null number")),
            }
        }

        fn u32_from_value<E: serde::de::Error>(value: Value) -> Result<u32, E> {
            let num = match value {
                Value::Number(token) => token,
                _ => return Err(E::custom("expected a number")),
            };
            u32_from_number(num)
        }

        let value = Value::deserialize(deserializer)?;
        let Value::Object(mut map) = value else {
            return Err(serde::de::Error::custom("Expected a JSON object"));
        };

        if let Some(Value::String(error)) = map.remove("error") {
            return Ok(OllamaResponse::Error { error });
        }

        let model = from_map!(map, "model", Value::String)?;
        let created_at = NaiveDateTime::parse_from_str(
            &from_map!(map, "created_at", Value::String)?,
            "%Y-%m-%dT%H:%M:%S%.fZ",
        )
        .map_err(serde::de::Error::custom)?;
        let done = from_map!(map, "done", Value::Bool)?;

        if done {
            let context = from_map!(map, "context", Value::Array)?
                .into_iter()
                .map(u32_from_value)
                .collect::<Result<Vec<_>, _>>()?;
            let total_duration = u32_from_number(from_map!(map, "total_duration", Value::Number)?)?;
            let load_duration = u32_from_number(from_map!(map, "load_duration", Value::Number)?)?;
            let prompt_eval_count =
                u32_from_number(from_map!(map, "prompt_eval_count", Value::Number)?)?;
            let prompt_eval_duration =
                u32_from_number(from_map!(map, "prompt_eval_duration", Value::Number)?)?;
            let eval_count = u32_from_number(from_map!(map, "eval_count", Value::Number)?)?;
            let eval_duration = u32_from_number(from_map!(map, "eval_duration", Value::Number)?)?;
            Ok(OllamaResponse::Finish {
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
            Ok(OllamaResponse::Progress {
                model,
                created_at,
                response,
            })
        }
    }
}

async fn submit_chat_message(
    mut db: DatabaseConnection,
    user: UserId,
    chat: FullChat,
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
        let context: Vec<u32> = chat
            .context
            .iter()
            .copied()
            .filter_map(identity)
            .map(|x| x as u32)
            .collect();
        let prompt = content.to_string();
        actix::spawn(async move {
            if let Err(error) = async {
                let message = assistant_message.id;

                let client = Client::new();
                let mut response = client
                    .post(format!("{}/api/generate", config.llm_api_url))
                    .json(&OllamaRequest {
                        model: "llama2:7b".to_string(),
                        prompt,
                        context: (!context.is_empty()).then_some(context),
                    })
                    .send()
                    .await?
                    .bytes_stream();

                let mut response_message = String::new();

                let (created_at, context) = 'message_loop: {
                    while let Some(bytes) = response.next().await {
                        let response: OllamaResponse = serde_json::from_slice(&bytes?)?;
                        // println!("message: {response:?}");
                        match response {
                            OllamaResponse::Error { error } => Err(error)?,
                            OllamaResponse::Progress { response, .. } => {
                                // append new tokens to response
                                response_message.push_str(&response);

                                state.write().unwrap().send_message(
                                    user,
                                    websocket::Message::Message {
                                        chat: chat.id,
                                        message,
                                        content: websocket::chat::Message::Token(response),
                                    },
                                );
                            }
                            OllamaResponse::Finish {
                                created_at,
                                context,
                                ..
                            } => {
                                break 'message_loop (created_at, context);
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

                // store chat context
                let context: Vec<Option<i32>> = context
                    .into_iter()
                    .map(|token| Some(token as i32))
                    .collect();
                update(&chat)
                    .set(chats_dsl::context.eq(context))
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
    };
    let chat: FullChat = insert_into(chats_dsl::chats)
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
) -> Result<FullChat, GetChatError> {
    // get associated chat
    let Some(chat): Option<FullChat> = chats_dsl::chats
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
    let chat = match get_chat_by_user(identity, body.chat, &mut db) {
        Ok(chat) => chat,
        Err(err) => return BadRequest(chat_message::Response::Failure(err.into())),
    };

    // place new chat message in database
    let (user_message, assistant_response) =
        submit_chat_message(db, chat.owner, chat, &body.message, state, config).await;

    // send newly created messages back
    Okay(chat_message::Response::Success {
        user_message,
        assistant_response,
    })
}

#[get("/list-chats")]
async fn list_chats_handler(identity: Identity, db: Data<Database>) -> impl Responder {
    println!("/list-chats");

    // get chats owned by user
    let user_id = identity.user_id().expect("Failed to get user id");
    let mut db = db.get().expect("Database not available");
    let chats: Vec<FullChat> = chats_dsl::chats
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
    let chat = match get_chat_by_user(identity, body.chat, &mut db) {
        Ok(chat) => chat,
        Err(err) => return BadRequest(check_chat::Response::Failure(err.into())),
    };

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
    let chat = match get_chat_by_user(identity, body.chat, &mut db) {
        Ok(chat) => chat,
        Err(err) => return BadRequest(list_messages::Response::Failure(err.into())),
    };

    // get messages
    let messages = messages_dsl::messages
        .filter(messages_dsl::chat.eq(chat.id))
        .order(messages_dsl::created.desc())
        .load(&mut db)
        .expect("Error querying database");

    // TODO: fetch in progress messages to deliver to the user as well

    Okay(list_messages::Response::Success { messages })
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
            .service(ws_handler)
            .service(admin_signup_handler)
            .service(create_user_handler)
            .service(login_handler)
            .service(logout_handler)
            .service(me_handler)
            .service(new_chat_handler)
            .service(chat_message_handler)
            .service(list_chats_handler)
            .service(check_chat_handler)
            .service(list_messages_handler)
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
