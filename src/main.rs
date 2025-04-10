
// https://rocket.rs/guide/v0.5/overview/
#[macro_use] extern crate rocket;
use rocket::fs::FileServer;
use rocket::tokio::io::AsyncWriteExt;
use rocket::serde::Deserialize;
use serde_json::Value;
use simple_backend;
use sqlite::{self, Connection};


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


#[get("/fetch2d")]
async fn _fetch() -> Result<String, String> {
    fetch2d().await
}


#[allow(unused)]
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


#[launch]
fn rocket() -> _ {
    let conns = Connection::open("OurApp.db").expect("Failed to open database");
    let query = "CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )";
    let query2 = "CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
        )";
    conns.execute(query).expect("Failed to execute table");
    conns.execute(query2).expect("Failed to execute table2");

    rocket::build()
    .attach(simple_backend::stage(conns))
    // .mount("/", routes![simple_backend::index, simple_backend::render_login])
    // .manage(DbConn {
    //     conn: Mutex::new(conns)
    // })
    // .mount("/hello", routes![world])
    // .mount("/hi", routes![world])
    // .mount("/getfile", routes![return_file_content])
    .mount("/", FileServer::from("files"))
    .configure(rocket::Config::figment().merge(("address", "0.0.0.0")))
    
}


