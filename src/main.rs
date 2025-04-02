use std::io;
// https://rocket.rs/guide/v0.5/overview/
#[macro_use] extern crate rocket;

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

#[launch]
fn rocket() -> _ {
    rocket::build()
    .mount("/", routes![bba])
    .mount("/hello", routes![world])
    .mount("/hi", routes![world])
    .mount("/getfile", routes![return_file_content])
}
