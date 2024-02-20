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
use actix_web::web::{self, Data, Json};
use actix_web::{get, post, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws::{self, WsResponseBuilder};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{NaiveDateTime, Utc};
use diesel::insert_into;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::Insertable;

use serde::Serialize;
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
#[diesel(table_name = shared::schema::chats)]
struct NewChat<'a> {
    name: &'a str,
    owner: UserId,
    created: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = shared::schema::messages)]
struct NewMessage<'a> {
    chat: ChatId,
    author: AuthorType,
    content: &'a str,
    created: NaiveDateTime,
}

async fn submit_chat_message(
    db: &mut DatabaseConnection,
    user: UserId,
    chat: ChatId,
    content: &str,
) -> (Message, Message) {
    // put new message into database
    let now = Utc::now().naive_utc();
    let new_message = NewMessage {
        chat,
        author: AuthorType::User,
        content,
        created: now,
    };
    let user_message: Message = insert_into(messages_dsl::messages)
        .values(&new_message)
        .get_result(db)
        .expect("Error inserting message into new chat");

    // put empty assistant response into database
    let assistant_message = NewMessage {
        chat,
        author: AuthorType::AssistantResponding,
        content: "",
        created: now,
    };
    let assistant_message: Message = insert_into(messages_dsl::messages)
        .values(&assistant_message)
        .get_result(db)
        .expect("Error inserting assistant message into new chat");

    // TODO: code here to spawn a new thread to query the llm api and start sending message packets back
    let _user = user; // spawn a new task here

    (user_message, assistant_message)
}

#[post("/new-chat")]
async fn new_chat_handler(
    identity: Identity,
    db: Data<Database>,
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
    let chat: Chat = insert_into(chats_dsl::chats)
        .values(&chat)
        .get_result(&mut db)
        .expect("Error insterting new chat");

    // place new chat message in database
    let (user_message, assistant_response) =
        submit_chat_message(&mut db, user_id, chat.id, &body.initial_message).await;

    // send chat id and assistant message id back
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
        submit_chat_message(&mut db, chat.owner, body.chat, &body.message).await;

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
    let chats: Vec<Chat> = chats_dsl::chats
        .filter(chats_dsl::owner.eq(user_id))
        .load(&mut db)
        .expect("Error querying database");

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

#[get("/list-messages")]
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
    let admin_signup = env::var("ADMIN_SIGNUP") == Ok("TRUE".to_string());
    let host_addr = format!("0.0.0.0:{}", port);

    println!("port: {port}");
    println!("database_url: {database_url}");
    println!("redis_url: {redis_url}");
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
    let config = Config { admin_signup };

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
