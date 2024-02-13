use actix_files as fs;
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = std::env::var("PORT").unwrap();
    println!("Running on {}", port);
    HttpServer::new(|| {
        App::new()
            // Serve static files from the directory where your frontend assets are located
            .service(fs::Files::new("/", "./front/dist").index_file("index.html"))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}