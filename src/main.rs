use std::env;

use actix_files as fs;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::RedisSessionStore, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::web::{self, Data};
use actix_web::{get, post, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder};
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::insert_into;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::Insertable;
use shared::model::{FullUser, User};
use shared::create_user::PasswordValidationError;

use shared::{login, me, create_user};

use crate::schema::users::dsl::*;

mod schema;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type PoolConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

struct AdminSignup(bool);

fn validate_password(_password: &str) -> Result<(), PasswordValidationError> {
    Ok(()) // no validation for now
}

fn encrypt_password(name: &str, password: &str) -> String {
    hash(format!("{}#{}", name, password), DEFAULT_COST).expect("Error hashing password")
}

fn check_password(user: &FullUser, password: &str) -> bool {
    verify(
        format!("{}#{}", user.username, password),
        &user.password_hash,
    )
    .expect("Error decrypting password")
}

trait UserFromIdentity {
    fn user(&self, db: &mut PoolConnection) -> Option<User>;
}

impl UserFromIdentity for Identity {
    fn user(&self, db: &mut PoolConnection) -> Option<User> {
        let user_id = self.id().ok()?.parse::<i32>().ok()?;
        users
            .find(user_id)
            .first::<FullUser>(db)
            .optional()
            .ok()?
            .map(Into::into)
    }
}

impl UserFromIdentity for Option<Identity> {
    fn user(&self, db: &mut PoolConnection) -> Option<User> {
        self.as_ref().and_then(|ident| ident.user(db))
    }
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser<'a> {
    username: &'a str,
    email: &'a str,
    password_hash: &'a str,
    admin: bool,
}

#[post("/admin-signup")]
async fn admin_signup_handler(
    body: web::Json<create_user::Request>,
    db: Data<Pool>,
    admin_signup_enabled: Data<AdminSignup>,
) -> impl Responder {
    // check if admin signup is enabled
    if !admin_signup_enabled.get_ref().0 {
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
        return HttpResponse::BadRequest()
            .json(create_user::Response::Failure(create_user::FailureReason::UserExists));
    }

    // Prepare the new user data
    let new_user = NewUser {
        username: &body.username,
        email: &body.email,
        password_hash: &encrypt_password(&body.username, &body.password),
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
    if !check_password(&user, &body.password) {
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
        Some(user) => me::Response::User(user),
    };
    HttpResponse::Ok().json(response)
}

#[post("/logout")]
async fn logout_handler(user: Identity) -> impl Responder {
    println!("/logout");
    user.logout();
    HttpResponse::Ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting");

    // env vars
    let identity_secret = env::var("IDENTITY_SECRET").expect("IDENTITY_SECRET must be set");
    let port = env::var("PORT").expect("PORT must be set");
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url = env::var("REDIS_URL").unwrap_or("redis://127.0.0.1:6379".to_string());
    let admin_signup = env::var("ADMIN_SIGNUP") == Ok("TRUE".to_string());
    let host_addr = format!("localhost:{}", port);

    println!("port: {port}");
    println!("database_url: {database_url}");
    println!("redis_url: {redis_url}");
    println!("admin_signup: {admin_signup}");

    // setup db connection
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool: Pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    println!("Connected to database");

    // setup redis connection
    let redis = RedisSessionStore::new(redis_url).await.unwrap();
    println!("Connected to redis");

    // serve app
    println!("Running on {}", host_addr);
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .app_data(Data::new(AdminSignup(admin_signup)))
            .wrap(IdentityMiddleware::default())
            .wrap(SessionMiddleware::new(
                redis.clone(),
                Key::from(identity_secret.as_bytes()),
            ))
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
