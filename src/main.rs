use std::io;
use std::path::Path;
// https://rocket.rs/guide/v0.5/overview/
#[macro_use] extern crate rocket;
use rocket::fs::{FileServer, NamedFile};
use rocket::tokio::io::AsyncWriteExt;
use rocket::serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Holiday {
    pub date: String,
    pub name: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct Live {
    pub date: String,
    pub set: String,
    pub time: String,
    pub twod: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ResultItem {
    pub history_id: String,
    pub open_time: String,
    pub set: String,
    pub stock_date: String,
    pub stock_datetime: String,
    pub twod: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub holiday: Holiday,
    pub live: Live,
    pub result: Vec<ResultItem>,
    pub server_time: String,
}

#[get("/")]
fn bba() -> String {
    "Hello, World".to_owned()
}

#[get("/fetch2d")]
async fn fetch() -> Result<String, String> {
    fetch2d().await
}



async fn fetch2d() -> Result<String, String> {
    let url = "https://api.thaistock2d.com/live";

    let response = reqwest::get(url)
        .await
        .map_err(|err| err.to_string())?;

    if response.status().is_success() {
        let body = response.text().await.map_err(|err| err.to_string())?;
        let parsed_json: Value = serde_json::from_str(&body).map_err(|err| err.to_string())?;
        
        let pretty_json = serde_json::to_string_pretty(&parsed_json).map_err(|err| err.to_string())?;
        let mut file = rocket::tokio::fs::File::create("files/live_data.json").await.map_err(|err| err.to_string())?;
        file.write_all(pretty_json.as_bytes())
            .await
            .map_err(|err| err.to_string())?;
        // println!("Response Body: {}", pretty_json);
        let api_response: ApiResponse = serde_json::from_str(&body).map_err(|err| err.to_string())?;
        
        
        println!("{:#?}", api_response);
        
        // Return a success message with some of the data
        Ok(format!("Server time: {}\n{:#?}", api_response.server_time, api_response))
        
    } else {
        Err("Failed to fetch data".to_owned())
    }
}

#[get("/world")]
fn world() -> &'static str {
    "Hello, test World!!!"
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
    .mount("/", routes![bba, get_pdf, fetch])
    .mount("/hello", routes![world])
    .mount("/hi", routes![world])
    .mount("/getfile", routes![return_file_content])
    .mount("/", FileServer::from("files"))
    
}


