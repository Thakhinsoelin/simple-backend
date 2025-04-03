use std::io;
use std::path::Path;
// https://rocket.rs/guide/v0.5/overview/
#[macro_use] extern crate rocket;
use rocket::fs::{FileServer, NamedFile};


#[get("/")]
fn bba() -> String {
    "Hello, World".to_owned()
}

#[get("/world")]
fn world() -> &'static str {
    "Hello, Nigger World!!!"
}

#[get("/<filename>")]
async fn return_file_content(filename: &str) -> String {
    let file: Result<String, io::Error> = rocket::tokio::fs::read_to_string(filename).await;
    match file {
        Ok(content) => content,
        Err(value) => {
            format!("Error: {}, requested file not found", value)
        }
    }
}

#[get("/getpdf")]
async fn get_pdf() -> Option<NamedFile> {
    // Get the path to the 'example.pdf' file at the crate root
    let path = Path::new("28.3.2025အစီအစဉ်.pdf");

    // Serve the PDF file
    NamedFile::open(path).await.ok()
}


#[launch]
fn rocket() -> _ {
    rocket::build()
    .mount("/", routes![bba, get_pdf])
    .mount("/hello", routes![world])
    .mount("/hi", routes![world])
    .mount("/getfile", routes![return_file_content])
    .mount("/public", FileServer::from("files"))
    
}
