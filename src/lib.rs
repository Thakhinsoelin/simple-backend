#[macro_use] extern crate rocket;

use rocket::tokio::io::AsyncReadExt;
use serde::{Serialize, Deserialize};
use handlebars::Handlebars;
use rocket::response::content::RawHtml;
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

#[get("/")]
pub async fn index(/*state: &State<AppState::AppState>*/) -> Result<RawHtml<String>, String> {
    let mut handlebars = Handlebars::new();
    let mut file = rocket::tokio::fs::File::open("views/dashboard.ejs").await.map_err(|err| err.to_string())?;
    let mut template_string = String::new();
    file.read_to_string(&mut template_string).await.map_err(|err| err.to_string())?;


    handlebars.register_template_string("hometem", template_string).map_err(|err| err.to_string())?;

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
    let result = handlebars.render("hometem", &posts).map_err(|err| err.to_string())?;
    // Simulate req.user and conditional rendering.
    // let user_present = true; // Replace with your user authentication logic
    Ok(RawHtml(result))
    
}

