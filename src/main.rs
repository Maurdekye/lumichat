use actix_files as fs;
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Running");
    HttpServer::new(|| {
        App::new()
            // Serve static files from the directory where your frontend assets are located
            .service(fs::Files::new("/", "./front/dist").index_file("index.html"))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}