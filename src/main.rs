use std::env;

use actix_files as fs;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::RedisSessionStore, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::web::{self, Data};
use actix_web::{post, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder};
use bcrypt::{hash, DEFAULT_COST};
use diesel::insert_into;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::Insertable;
use shared::signup::PasswordValidationError;

use shared::{model::User, login, me, signup};

use crate::schema::users::dsl::*;

mod schema;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

fn validate_password(_password: &str) -> Result<(), PasswordValidationError> {
    Ok(()) // no validation for now
}

fn encrypt_password(name: &str, password: &str) -> String {
    hash(format!("{}#{}", name, password), DEFAULT_COST).expect("Error hashing password")
}

fn check_password(user: &User, password: &str) -> bool {
    encrypt_password(&user.username, password) == user.password_hash
}


#[derive(Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser<'a> {
    username: &'a str,
    email: &'a str,
    password_hash: &'a str,
}

#[post("/signup")]
async fn signup_handler(
    request: HttpRequest,
    body: web::Json<signup::Request>,
    db: Data<Pool>,
) -> impl Responder {
    let mut db = db.get().expect("Database not available");

    // decode request
    let signup_request = body.into_inner();

    // validate password
    if let Err(validation_error) = validate_password(&signup_request.password) {
        return HttpResponse::BadRequest().json(signup::Response {
            success: false,
            result: signup::ResponseType::InvalidPassword(validation_error)
        });
    }

    // check for existing users
    let user_query = users
        .filter(username.eq(&signup_request.username))
        .or_filter(email.eq(&signup_request.email))
        .first::<User>(&mut db)
        .optional()
        .expect("Error querying database");

    if let Some(_) = user_query {
        return HttpResponse::BadRequest().json(signup::Response {
            success: false,
            result: signup::ResponseType::UserExists
        });
    }

    // Prepare the new user data
    let new_user = NewUser {
        username: &signup_request.username,
        email: &signup_request.email,
        password_hash: &encrypt_password(&signup_request.username, &signup_request.password),
    };

    // Insert new user into the database
    let new_user: User = insert_into(users)
        .values(&new_user)
        .get_result(&mut db)
        .expect("Error inserting new user");

    // Log user in
    Identity::login(&request.extensions(), new_user.id.to_string()).unwrap();
    HttpResponse::Ok().json(signup::Response {
        success: true,
        result: signup::ResponseType::Success(new_user)
    })
}

#[post("/login")]
async fn login_handler(
    request: HttpRequest,
    body: web::Json<login::Request>,
    db: Data<Pool>,
) -> impl Responder {
    println!("login request recieved");
    let mut db = db.get().expect("Database not available");

    // decode request
    let login_request = body.into_inner();
    println!("login request body:\n{login_request:#?}");

    // check database
    let user_query = users
        .filter(
            username
                .eq(&login_request.identifier)
                .or(email.eq(&login_request.identifier)),
        )
        .first::<User>(&mut db)
        .optional()
        .expect("Error querying database");

    let Some(user) = user_query else {
        return HttpResponse::Unauthorized().json(login::Response {
            success: false,
            message: "Invalid Password".to_string(),
        });
    };

    // check password
    if !check_password(&user, &login_request.password) {
        return HttpResponse::Unauthorized().json(login::Response {
            success: false,
            message: "Invalid Password".to_string(),
        });
    }

    // log user in
    Identity::login(&request.extensions(), user.id.to_string()).unwrap();
    HttpResponse::Ok().json(login::Response {
        success: false,
        message: "Successfully logged in".to_string(),
    })
}

#[post("/me")]
async fn me_handler(user: Option<Identity>, db: Data<Pool>) -> impl Responder {
    let response = match user {
        None => me::Response {
            identity: me::UserIdentity::Anonymous,
            user: None,
        },
        Some(user) => {
            let mut db = db.get().expect("Database not available");
            let user_id = user.id().unwrap().parse::<i32>().unwrap();
            let user = users
                .find(user_id)
                .first::<User>(&mut db)
                .optional()
                .unwrap();
            me::Response {
                identity: me::UserIdentity::User,
                user,
            }
        }
    };
    web::Json(response)
}

#[post("/logout")]
async fn logout_handler(user: Identity) -> impl Responder {
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
    let host_addr = format!("localhost:{}", port);

    println!("port: {port}");
    println!("database_url: {database_url}");
    println!("redis_url: {redis_url}");

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
            .wrap(IdentityMiddleware::default())
            .wrap(SessionMiddleware::new(
                redis.clone(),
                Key::from(identity_secret.as_bytes()),
            ))
            .service(signup_handler)
            .service(login_handler)
            .service(logout_handler)
            .service(me_handler)
            .service(fs::Files::new("/", "./front/dist").index_file("index.html"))
    })
    .bind(host_addr)?
    .run()
    .await
}
