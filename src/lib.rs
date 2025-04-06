#[macro_use] extern crate rocket;

use tera::{Context, Tera};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use rocket::{response::content::RawHtml, State};
use dotenv::dotenv;
use sqlite;

#[allow(non_snake_case)]
mod AppState;

// Simulated Posts
#[derive(Serialize, Deserialize)]
pub struct Post {
    id: u32,
    title: String,
    content: String,
    authorid: u32,
}

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = match Tera::new("templates/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec![]);
        
        tera
    };
}


#[get("/")]
pub async fn index(conn: &State<AppState::DbConn>) -> Result<RawHtml<String>, String> {
    let mut context = Context::new();
    let conn = conn.0.lock().unwrap();
    // Simulate database query results.
    let posts: Vec<Post> = vec![
        Post {
            id: 1,
            title: "Post 1".to_string(),
            content: "Content 1".to_string(),
            authorid: 1,
        },
        Post {
            id: 2,
            title: "Post 2".to_string(),
            content: "Content 2".to_string(),
            authorid: 1,
        },
    ];
    // Simulate error
    let error_messages = vec![
        "Error 1: This is a Simulated Error".to_string()
    ];
    context.insert("errors", &error_messages);
    let crap = match TEMPLATES.render("homepage.html", &context) {
        Ok(kind) => {
            println!("{}", kind);
            kind
        },
        Err(err) => {
            err.to_string()
        },
    };
    println!("{}", crap);
    Ok(RawHtml(crap))
    
}

#[get("/login")]
pub async fn render_login(conn: &State<AppState::DbConn>) -> Result<RawHtml<String>, String> {
    let conn = conn.0.lock().unwrap();
    let mut context = Context::new();
    let errors: Vec<String> = Vec::new();

    context.insert("errors", &errors);
    let crap = TEMPLATES.render("homepage.html", &context).map_err(|err| err.to_string())?;
    Ok(RawHtml(crap))
}