use std::env;

use actix_files as fs;
use actix_web::web::Data;
use actix_web::{App, HttpServer};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = env::var("PORT").expect("PORT must be set");
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let host_addr = format!("0.0.0.0:{}", port);

    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool: Pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    println!("Running on {}", host_addr);
    
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .service(fs::Files::new("/", "./front/dist").index_file("index.html"))
    })
    .bind(host_addr)?
    .run()
    .await
}
