use std::collections::HashMap;
use std::default::Default;
use std::env;
use std::sync::RwLock;

use actix::{Actor, Addr, StreamHandler};
use actix_files as fs;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::RedisSessionStore, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::web::{self, Data};
use actix_web::{get, post, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws::{self, WsResponseBuilder};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{NaiveDateTime, Utc};
use diesel::insert_into;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::Insertable;
use shared::create_user::PasswordValidationError;

use shared::model::{AuthorType, Chat, FullUser, Message};
use shared::{create_user, login, me, new_chat, websocket};

use shared::schema::chats::dsl::*;
use shared::schema::messages::dsl::*;
use shared::schema::users::dsl::*;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type PoolConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

fn validate_password(_password: &str) -> Result<(), PasswordValidationError> {
    Ok(()) // no validation for now
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

struct State {
    admin_signup: bool,
    websock_connections: RwLock<HashMap<i32, Vec<Addr<Websocket>>>>,
}

trait UserIdFromIdentity {
    fn user_id(&self) -> Option<i32>;
}

impl UserIdFromIdentity for Identity {
    fn user_id(&self) -> Option<i32> {
        self.id().ok()?.parse::<i32>().ok()
    }
}

trait FullUserFromIdentity {
    fn user(&self, db: &mut PoolConnection) -> Option<FullUser>;
}

impl FullUserFromIdentity for Identity {
    fn user(&self, db: &mut PoolConnection) -> Option<FullUser> {
        let user_id = self.user_id()?;
        users
            .find(user_id)
            .first::<FullUser>(db)
            .optional()
            .ok()?
            .map(Into::into)
    }
}

impl FullUserFromIdentity for Option<Identity> {
    fn user(&self, db: &mut PoolConnection) -> Option<FullUser> {
        self.as_ref().and_then(|ident| ident.user(db))
    }
}

// Websocket management

#[get("/ws")]
async fn ws_handler(
    request: HttpRequest,
    stream: web::Payload,
    identity: Identity,
    state: Data<State>,
) -> impl Responder {
    let user_id = identity.user_id().expect("Failed to get user id");
    let (websocket_address, response) = WsResponseBuilder::new(Websocket, &request, stream)
        .start_with_addr()
        .expect("Unable to create websocket connection");
    state
        .websock_connections
        .write()
        .unwrap()
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
    body: web::Json<create_user::Request>,
    db: Data<Pool>,
    state: Data<State>,
) -> impl Responder {
    // check if admin signup is enabled
    if !state.admin_signup {
        return HttpResponse::Unauthorized().finish();
    }

    // proceed to user creation
    let mut db = db.get().expect("Database not available");
    create_user_inner(body, &mut db, true).await
}

#[post("/create-user")]
async fn create_user_handler(
    identity: Identity,
    body: web::Json<create_user::Request>,
    db: Data<Pool>,
) -> impl Responder {
    // check if operating user is an admin
    let mut db = db.get().expect("Database not available");
    let user = identity.user(&mut db).expect("Unable to load user profile");
    if !user.admin {
        return HttpResponse::Unauthorized().finish();
    }

    // proceed to user creation
    create_user_inner(body, &mut db, false).await
}

async fn create_user_inner(
    body: web::Json<create_user::Request>,
    db: &mut PoolConnection,
    make_admin: bool,
) -> HttpResponse {
    // decode request
    let body = body.into_inner();
    println!("/create-user: {body:#?}");

    // validate password
    if let Err(validation_error) = validate_password(&body.password) {
        return HttpResponse::BadRequest().json(create_user::Response::Failure(
            create_user::FailureReason::InvalidPassword(validation_error),
        ));
    }

    // check for existing users
    let user_query = users
        .filter(username.eq(&body.username))
        .or_filter(email.eq(&body.email))
        .first::<FullUser>(db)
        .optional()
        .expect("Error querying database");

    if let Some(_) = user_query {
        return HttpResponse::BadRequest().json(create_user::Response::Failure(
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
    let new_user: FullUser = insert_into(users)
        .values(&new_user)
        .get_result(db)
        .expect("Error inserting new user");

    // Respond successfully
    HttpResponse::Ok().json(create_user::Response::Success(new_user.into()))
}

#[post("/login")]
async fn login_handler(
    user: Option<Identity>,
    request: HttpRequest,
    body: web::Json<login::Request>,
    db: Data<Pool>,
) -> impl Responder {
    // check if already logged in
    if user.is_some() {
        return HttpResponse::BadRequest().json(login::Response::Failure(
            login::FailureReason::AlreadyLoggedIn,
        ));
    }

    // decode request
    let body = body.into_inner();
    println!("/login: {body:#?}");

    // check database for user
    let mut db = db.get().expect("Database not available");
    let user_query = users
        .filter(username.eq(&body.identifier).or(email.eq(&body.identifier)))
        .first::<FullUser>(&mut db)
        .optional()
        .expect("Error querying database");

    let Some(user) = user_query else {
        return HttpResponse::BadRequest().json(login::Response::Failure(
            login::FailureReason::UserDoesNotExist,
        ));
    };

    // check password
    if !verify(&body.password, &user.password_hash).expect("Error decrypting password") {
        return HttpResponse::BadRequest().json(login::Response::Failure(
            login::FailureReason::InvalidPassword,
        ));
    }

    // log user in
    Identity::login(&request.extensions(), user.id.to_string()).unwrap();
    HttpResponse::Ok().json(login::Response::Success(user.into()))
}

#[get("/me")]
async fn me_handler(identity: Option<Identity>, db: Data<Pool>) -> impl Responder {
    println!("/me");
    let mut db = db.get().expect("Database not available");
    let response = match identity.user(&mut db) {
        None => me::Response::Anonymous,
        Some(user) => me::Response::User(user.into()),
    };
    HttpResponse::Ok().json(response)
}

#[post("/logout")]
async fn logout_handler(user: Identity) -> impl Responder {
    println!("/logout");
    user.logout();
    HttpResponse::Ok()
}

// Chatting

#[derive(Insertable)]
#[diesel(table_name = shared::schema::chats)]
struct NewChat<'a> {
    name: &'a str,
    owner: i32,
    created: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = shared::schema::messages)]
struct NewMessage<'a> {
    chat_id: i32,
    author: AuthorType,
    content: &'a str,
    created: NaiveDateTime,
}

#[get("/new-chat")]
async fn new_chat_handler(
    user: Identity,
    db: Data<Pool>,
    body: web::Json<new_chat::Request>,
) -> impl Responder {
    // decode request
    let body = body.into_inner();
    println!("/new-chat: {body:#?}");

    // put new chat into database
    let user_id: i32 = user.id().unwrap().parse().unwrap();
    let mut db = db.get().expect("Database not available");
    let now = Utc::now().naive_utc();
    let new_chat = NewChat {
        name: "New Chat",
        owner: user_id,
        created: now.clone(),
    };
    let new_chat: Chat = insert_into(chats)
        .values(&new_chat)
        .get_result(&mut db)
        .expect("Error insterting new chat");

    // put new message into database
    let new_message = NewMessage {
        chat_id: new_chat.id,
        author: AuthorType::User,
        content: &body.initial_message,
        created: now,
    };
    let new_message: Message = insert_into(messages)
        .values(&new_message)
        .get_result(&mut db)
        .expect("Error inserting message into new chat");

    // send chat and message back
    HttpResponse::Ok().json(new_chat::Response {
        chat: new_chat,
        messages: vec![new_message],
    })
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
    let pool: Pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    println!("Connected to database");

    // connect to redis
    let redis = RedisSessionStore::new(redis_url).await.unwrap();
    println!("Connected to redis");

    // serve app
    println!("Running on {}", host_addr);
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .app_data(Data::new(State {
                admin_signup,
                websock_connections: Default::default(),
            }))
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
            .service(fs::Files::new("/", "./front/dist").index_file("index.html"))
    })
    .bind(host_addr)?
    .run()
    .await
}
