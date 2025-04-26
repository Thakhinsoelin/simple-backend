#[macro_use] extern crate rocket;

use std::{sync::Mutex, time::{SystemTime, UNIX_EPOCH}};
use cookie::time::Duration;
use jsonwebtoken::{encode, EncodingKey};
use rocket::{ http::{private::cookie, ContentType, Status}, response::Redirect};
use tera::{Context, Tera};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use rocket::{response::content::RawHtml,
    http::{Cookie, CookieJar, SameSite},
    State};
use rocket::request::{FromRequest, Outcome};
use rocket::fairing::AdHoc;
use rocket::form::{Form, ValueField};
use sqlite::{self, Connection};
use bcrypt::{verify, DEFAULT_COST};
use std::option::Option;
use std::sync::LockResult;
use ammonia::url::quirks::username;
use chrono::{ Utc};

#[allow(non_snake_case)]
mod AppState;
use AppState::DbConn;
use regex::Regex;

#[derive(FromForm, Deserialize)]
pub struct LoginForm<'r> {
    pub username: &'r str,
    pub password: &'r str,
}





#[derive(FromForm)]
pub struct PostForm<'r> {
    pub title: &'r str,
    pub body: &'r str,
}

#[derive(Debug)]
pub struct OptionalUser(pub Option<User>); // If the user might not be authenticated

// Simulated Posts
#[derive(Serialize, Deserialize, Debug)]
pub struct Post {
    id: i64,
    create_date: String,
    title: String,
    content: String,
    authorid: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    sky_color: String,
    userid: i32,
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub userid: i64,
    pub username: String,
    pub exp: usize, // Include the expiration claim if you're using it
    // Add other user fields as needed
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
        tera.autoescape_on(vec![".html", ".sql"]);
        
        tera
    };
}

pub enum MyResponse {
    Html(RawHtml<String>),
    Redirect(Redirect),
    Error(String),
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for MyResponse {
    fn respond_to(self, req: &'r rocket::request::Request<'_>) -> Result<rocket::response::Response<'o>, Status> {
        match self {
            MyResponse::Html(html) => html.respond_to(req),
            MyResponse::Redirect(redirect) => redirect.respond_to(req),
            MyResponse::Error(err) => rocket::Response::build()
                .status(Status::BadRequest) // Or another appropriate status
                .header(ContentType::Plain)
                .sized_body(err.len(), std::io::Cursor::new(err))
                .ok(),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OptionalUser {
    type Error = ();

    async fn from_request(request: &'r rocket::request::Request<'_>) -> Outcome<Self, Self::Error> {
        let jwt_secret = dotenv::var("JWTSECRET").unwrap();
        let jwt_cookie = request.cookies().get("ourSimpleApp");

        match (jwt_secret, jwt_cookie) {
            (secret, Some(cookie)) => {
                let token = cookie.value();
                let decoding_key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
                let validation = jsonwebtoken::Validation::default(); // You can customize validation rules

                match jsonwebtoken::decode::<User>(&token, &decoding_key, &validation) {
                    Ok(token_data) => Outcome::Success(OptionalUser(Some(token_data.claims))),
                    Err(err) => {
                        eprintln!("JWT verification error: {:?}", err);
                        Outcome::Success(OptionalUser(None)) // Token invalid, user is not authenticated
                    }
                }
            }
            _ => Outcome::Success(OptionalUser(None)), // No secret or no cookie, user is not authenticated
        }
    }
}


#[get("/post/<id>")]
pub fn get_post(id: i64, user: OptionalUser, state: &State<DbConn>) -> MyResponse {
    let mut errors = Vec::new();
    let mut context = Context::new();
    let mut posts: Vec<Post> = Vec::new();
    let mut post_id;
    let mut post_created_date = String::new();
    let mut post_title = String::new();
    let mut post_body = String::new();
    let mut author_id;
    match state.conn.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare("SELECT * FROM posts WHERE id = ?") {
                Ok(value) => value,
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            match statement.bind((1, id)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            match statement.next() {
                Ok(res)=> {    
                    post_id = match statement.read::<i64, _>("id") {
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Error("that post don't exist".to_string())
                        }
                    };
                    post_created_date = match statement.read::<String, _>("createdDate"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Error("That post don't exist".to_string())
                        }
                    };
                    post_title = match statement.read::<String, _>("title"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };
                    post_body = match statement.read::<String, _>("body"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };
                    author_id = match statement.read::<i64, _>("authorid"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };
                },
                Err(_) => {
                    println!("user table query failed");
                    return MyResponse::Error("table failed".to_string());

                }
            }

        },
        Err(_) => {
            return MyResponse::Html(RawHtml("mutex lock is failed".to_string()));
        }
    }
    let post = Post {
        id: post_id,
        create_date: post_created_date,
        title: post_title,
        content: post_body,
        authorid: author_id
    };

    if let Some(user) = user.0 {
        context.insert("post", &post);
        context.insert("user", &user);
        context.insert("username", user.username.as_str());
    };
    match TEMPLATES.render("single-post.html", &context) {
        Ok(result) => MyResponse::Html(RawHtml(result)),
        Err(err_code) => {
            MyResponse::Error(err_code.to_string())
        }
    }
}

#[post("/delete-post/<id>")]
fn delete_post(id: i64, user: OptionalUser, state: &State<DbConn>) -> MyResponse {
    let mut errors = Vec::new();
    let mut context = Context::new();
    let mut post_id;
    let mut post_created_date = String::new();
    let mut post_title = String::new();
    let mut post_body = String::new();
    let mut author_id;

    let mut param_user_id = 0;
    match state.conn.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?") {
                Ok(value) => value,
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            match statement.bind((1, id)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            match statement.next() {
                Ok(res)=> {
                    post_id = match statement.read::<i64, _>("id") {
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post_created_date = match statement.read::<String, _>("createdDate"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post_title = match statement.read::<String, _>("title"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post_body = match statement.read::<String, _>("body"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    author_id = match statement.read::<i64, _>("authorid"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                },
                Err(_) => {
                    println!("user table query failed");
                    return MyResponse::Error("table failed".to_string());

                }
            }

        },
        Err(_) => {
            return MyResponse::Html(RawHtml("mutex lock is failed".to_string()));
        }
    }

    let post = Post {
        id: post_id,
        create_date: post_created_date,
        title: post_title,
        content: post_body,
        authorid: author_id
    };
    if let Some(user) = user.0 {
        if post.authorid != user.userid {
            return MyResponse::Redirect(Redirect::to("/"))
        }
        param_user_id = user.userid;
        context.insert("post", &post);
        context.insert("user", &user);
        context.insert("username", user.username.as_str());
    };
    match state.conn.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare("DELETE FROM posts WHERE id = ?") {
                Ok(value) => value,
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            match statement.bind((1, id)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            match statement.next() {
                Ok(sqlite::State::Done) => {
                    println!("Post with id {} deleted successfully", param_user_id);
                    // Return a success response (e.g., redirect)
                    return MyResponse::Redirect(Redirect::to("/"));
                }
                Ok(sqlite::State::Row) => {
                    // DELETE statements should not return rows. This is unexpected.
                    eprintln!("Warning: DELETE statement returned rows unexpectedly.");
                    return MyResponse::Error("Unexpected response from DELETE query".to_string());
                }
                Err(code) => {
                    return MyResponse::Error(code.to_string());
                }
            };

        },
        Err(_) => {
            return MyResponse::Html(RawHtml("mutex lock is failed".to_string()));
        }
    }
}

#[get("/")]
pub fn index(user: OptionalUser, state: &State<DbConn>) -> MyResponse {
    let mut context = Context::new();
    
    let error_messages = vec![
        "Error 1: This is a Simulated Error".to_string()
    ];
    // Simulate database query results.
    let mut posts = Vec::new();
    // Simulate error
    if let Some(user) = user.0 {
        match state.conn.lock() {
            Ok(connection) =>{

                let query = "SELECT * FROM posts WHERE authorid = ?";
                for row in connection
                    .prepare(query)
                    .unwrap()
                    .into_iter()
                    .bind((1, user.userid))
                    .unwrap()
                    .map(|row| row.unwrap())
                {
                    let post_id = row.read::<i64,_>("id");
                    let post_created_date = row.read::<&str,_>("createdDate");
                    let post_title = row.read::<&str,_>("title");
                    let post_body = row.read::<&str,_>("body");
                    let post_author_id = row.read::<i64,_>("authorid");

                    let post = Post {
                        id: post_id,
                        create_date: post_created_date.to_owned(),
                        title: post_title.to_owned(),
                        content: post_body.to_owned(),
                        authorid: post_author_id
                    };
                    posts.push(post);

                }
                context.insert("user", &user);
                context.insert("posts", &posts);
                

                match TEMPLATES.render("dashboard.html", &context) {
                    Ok(result) => MyResponse::Html(RawHtml(result)),
                    Err(err_code) => {
                        MyResponse::Error(format!("{:?}",err_code.kind))
                    }
                }
            },
            Err(code) => return MyResponse::Error(code.to_string())
        }
    } else {
        context.insert("errors", &error_messages);
        match TEMPLATES.render("homepage.html", &context) {
            Ok(result) => MyResponse::Html(RawHtml(result)),
            Err(err_code) => {
                MyResponse::Error(err_code.to_string())
            }
        }

    }
    
    
}

#[get("/login")]
pub async fn render_login( _state: &State<DbConn>, /*jar: &CookieJar<'_>*/) -> MyResponse {
    let mut context = Context::new();
    let mut errors: Vec<String> = Vec::new();

    
    context.insert("errors", &errors);
    match TEMPLATES.render("login.html", &context) {
        Ok(result) => MyResponse::Html(RawHtml(result)),
        Err(err_code) => {
            MyResponse::Error(err_code.to_string())
        }
    }
}

#[get("/create-post")]
fn create_post(user: OptionalUser) -> MyResponse {
    let mut context = Context::new();
    let mut errors: Vec<String> = Vec::new();
    match user.0 {
        Some(user) => {
            context.insert("user", &user);
            context.insert("errors", &errors);
            match TEMPLATES.render("create-post.html", &context) {
                Ok(result) => MyResponse::Html(RawHtml(result)),
                Err(err_code) => {
                    return MyResponse::Error(err_code.to_string())
                }
            }
        },
        None => {
            return MyResponse::Redirect(Redirect::to("/"))
        }
    }
}

#[get("/edit-post/<id>")]
fn edit_post(id: i64, user: OptionalUser, state: &State<DbConn>) -> MyResponse {
    let mut context = Context::new();
    let mut errors: Vec<String> = Vec::new();
    let mut post = Post {
        id: 0,
        create_date: String::new(),
        title: String::new(),
        content: String::new(),
        authorid: 0,
    };
    match state.conn.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare("SELECT * FROM posts WHERE id = ?") {
                Ok(value) => value,
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            match statement.bind((1, id)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            match statement.next() {
                Ok(_) => {
                    post.id = match statement.read::<i64, _>("id") {
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post.create_date = match statement.read::<String, _>("createdDate"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post.title = match statement.read::<String, _>("title"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post.content = match statement.read::<String, _>("body"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post.authorid = match statement.read::<i64, _>("authorid") {
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    }
                }

                Err(code) => {
                    println!("SQL querty succeed in selecting the post of user id = {}", id);
                }
            };

        },
        Err(_) => {
            return MyResponse::Html(RawHtml("mutex lock is failed".to_string()));
        }
    }

    if post.id == 0 {
        return MyResponse::Redirect(Redirect::to("/"));
    }
    let mut userid = 0;
    match user.0 {
        Some(user) => {
            userid = user.userid;
        }
        None => {
            return MyResponse::Redirect(Redirect::to("/"));
        }
    }

    if userid != post.authorid {
        return MyResponse::Redirect(Redirect::to("/"));
    }
    context.insert("errors", &errors);
    context.insert("post", &post);
    context.insert("user", &true);
    match TEMPLATES.render("edit-post.html", &context) {
        Ok(result) => MyResponse::Html(RawHtml(result)),
        Err(err_code) => {
            return MyResponse::Error(err_code.to_string())
        }
    }
}

#[post("/create-post", data = "<post>")]
fn handle_create_post(user: OptionalUser, state: &State<DbConn>, post: Form<PostForm<'_>>) -> MyResponse {
    let post_form = post.into_inner();
    let mut context = Context::new();
    let mut errors = Vec::new();
    let mut does_user_exist: bool = false;
    let mut userr = User {
        userid: 0,
        username: "".to_string(),
        exp: 0,
    };
    match user.0 {
        Some(user) => { does_user_exist = true;  context.insert("user", &user); userr = user;},
        None => {
            return MyResponse::Redirect(Redirect::to("/"));
        }
    }
    if post_form.title.is_empty() || post_form.body.is_empty() {
        errors.push("title is empty or the body is empty. Please fill those".to_string());
        context.insert("errors", &errors);
        match TEMPLATES.render("create-post.html", &context) {
            Ok(result) => MyResponse::Html(RawHtml(result)),
            Err(err_code) =>  MyResponse::Error(err_code.to_string())
        };

    }

    let sanitized_title = ammonia::clean(&post_form.title);
    let sanitized_body= ammonia::clean(&post_form.body);
    if sanitized_title.is_empty() || sanitized_body.is_empty() {
        errors.push("title is empty or the body is empty. Please fill those".to_string());
        context.insert("errors", &errors);
        match TEMPLATES.render("create-post.html", &context) {
            Ok(result) => MyResponse::Html(RawHtml(result)),
            Err(err_code) =>  MyResponse::Error(err_code.to_string())
        };

    }
    
    //asat
    let mut last_inserted_row_id = 0;
    match state.conn.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)") {
                Ok(value) => value,
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            match statement.bind((1, &sanitized_title[..])){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };

            match statement.bind((2, &sanitized_body[..])){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };

            match statement.bind((3, userr.userid)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            let now = Utc::now();
            let iso_string = format!("{}", now.format("%Y-%m-%dT%H:%M:%S.%3fZ"));
            match statement.bind((4, iso_string.as_str())){
                Ok(_) => println!("post table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };

            match statement.next() {
                Ok(sqlite::State::Done) => {
                    // Return a success response (e.g., redirect)
                    println!("post table query succeed");
                }
                Ok(sqlite::State::Row) => {
                    // INSERT statements should not return rows. This is unexpected.
                    eprintln!("Warning: INSERT statement returned rows unexpectedly.");
                }
                Err(code) => {
                    return MyResponse::Error(code.to_string());
                }
            };

            let mut statement = match connection.prepare("SELECT last_insert_rowid()") {
                Ok(value) => value,
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };

            match statement.next() {
                Ok(_) => {
                    last_inserted_row_id = match statement.read::<i64, _>(0) {
                        Ok(row_id) => row_id,
                        Err(code) => { return MyResponse::Error(code.to_string()) }
                    };
                }
                Err(code) => {
                    return MyResponse::Error(code.to_string());
                }
            }

        },
        Err(_) => {
            return MyResponse::Html(RawHtml("mutex lock is failed".to_string()));
        }
    }

    let mut post_id= 0;

    let mut param_user_id = 0;
    match state.conn.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare("SELECT * FROM posts WHERE ROWID = ?") {
                Ok(value) => value,
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            match statement.bind((1, last_inserted_row_id)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            match statement.next() {
                Ok(res)=> {
                    post_id = match statement.read::<i64, _>("id") {
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                },
                Err(_) => {
                    println!("user table query failed");
                    return MyResponse::Error("table failed".to_string());

                }
            }

        },
        Err(_) => {
            return MyResponse::Html(RawHtml("mutex lock is failed".to_string()));
        }
    }


    MyResponse::Redirect(Redirect::to(format!("/post/{}", post_id)))

}

#[post("/edit-post/<id>", data = "<post>")]
fn handle_edit_post(id: i64, user: OptionalUser, state: &State<DbConn>, post: Form<PostForm<'_>>) -> MyResponse {
    let post_form = post.into_inner();
    let mut context = Context::new();
    let mut errors = Vec::new();
    let mut does_user_exist: bool = false;
    let mut userr = User {
        userid: 0,
        username: "".to_string(),
        exp: 0,
    };
    match user.0 {
        Some(user) => { does_user_exist = true;  context.insert("user", &user); userr = user;},
        None => {
            return MyResponse::Redirect(Redirect::to("/"));
        }
    }
    if post_form.title.is_empty() || post_form.body.is_empty() {
        errors.push("title is empty or the body is empty. Please fill those".to_string());
        context.insert("errors", &errors);
        match TEMPLATES.render("create-post.html", &context) {
            Ok(result) => MyResponse::Html(RawHtml(result)),
            Err(err_code) =>  MyResponse::Error(err_code.to_string())
        };

    }

    let sanitized_title = ammonia::clean(&post_form.title);
    let sanitized_body= ammonia::clean(&post_form.body);
    if sanitized_title.is_empty() || sanitized_body.is_empty() {
        errors.push("title is empty or the body is empty. Please fill those".to_string());
        context.insert("errors", &errors);
        match TEMPLATES.render("create-post.html", &context) {
            Ok(result) => MyResponse::Html(RawHtml(result)),
            Err(err_code) =>  MyResponse::Error(err_code.to_string())
        };

    }

    let mut post = Post {
        id: 0,
        create_date: String::new(),
        title: String::new(),
        content: String::new(),
        authorid: 0,
    };
    match state.conn.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare("SELECT * FROM posts WHERE id = ?") {
                Ok(value) => value,
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            match statement.bind((1, id)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            match statement.next() {
                Ok(_) => {
                    post.id = match statement.read::<i64, _>("id") {
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post.create_date = match statement.read::<String, _>("createdDate"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post.title = match statement.read::<String, _>("title"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post.content = match statement.read::<String, _>("body"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    };
                    post.authorid = match statement.read::<i64, _>("authorid") {
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Redirect(Redirect::to("/"))
                        }
                    }
                }

                Err(code) => {
                    println!("SQL querty succeed in selecting the post of user id = {}", id);
                }
            };

        },
        Err(_) => {
            return MyResponse::Html(RawHtml("mutex lock is failed".to_string()));
        }
    }

    if post.id == 0 {
        return MyResponse::Redirect(Redirect::to("/"));
    }

    if userr.userid != post.authorid {
        return MyResponse::Redirect(Redirect::to("/"));
    }

    match state.conn.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?") {
                Ok(value) => value,
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };
            match statement.bind((1, &sanitized_title[..])){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };

            match statement.bind((2, &sanitized_body[..])){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };

            match statement.bind((3, id)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    return MyResponse::Error(code.to_string())
                }
            };

            match statement.next() {
                Ok(sqlite::State::Done) => {
                    // Return a success response (e.g., redirect)
                    println!("post table query succeed");
                }
                Ok(sqlite::State::Row) => {
                    // INSERT statements should not return rows. This is unexpected.
                    eprintln!("Warning: UPDATE statement returned rows unexpectedly.");
                }
                Err(code) => {
                    return MyResponse::Error(code.to_string());
                }
            };


        },
        Err(_) => {
            return MyResponse::Html(RawHtml("mutex lock is failed".to_string()));
        }
    }
    MyResponse::Redirect(Redirect::to(format!("/post/{}", post.id)))
}

#[post("/login", data = "<form>")]
pub fn handle_login(state: &State<DbConn>, form: Form<LoginForm<'_>>, jar: &CookieJar<'_>) -> MyResponse {
    let mut errors: Vec<String> = Vec::new();
    let mut context = Context::new();
    let u;
    let p;
    let userid;

    let mut username: &str;
    let mut password: &str;

    match state.conn.lock() {
        Ok(connection) => {
            let loginform = form.into_inner();
            username = if loginform.username.is_empty() {
                ""
            } else {
                loginform.username
            };
            password = if loginform.password.is_empty() {
                ""
            } else {
                loginform.password
            };

            username = username.trim();
            password = password.trim();

            if username.len() > 32 {
                errors.push(String::from("The amount of characters in the name should not exceed 32"));
            }

            if password.len() > 32 {
                errors.push(String::from("The amount of characters in the password should not exceed 32"));
            }

            if username == "" {
                errors.push(String::from("Invalid Username / Password"));
            }

            if password == "" {
                errors.push(String::from("Invalid Username / Password"));
            }
            println!("username: {}\npassword: {}\n", username, password);
            if errors.len() > 0 {
                context.insert("errors", &errors);
                let crap = match TEMPLATES.render("login.html", &context) {
                    Ok(cp) =>  cp,
                    Err(cp) => return MyResponse::Error(cp.to_string())
                };
                return MyResponse::Html(RawHtml(crap))
            }

            let mut user_in_question_statement = match connection.prepare("SELECT * FROM users WHERE USERNAME = ?") {
                Ok(value) => value,
                Err(_code) => {
                    errors.push(String::from("Invalid Username / Password".to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("login.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            match user_in_question_statement.bind((1, username)){
                Ok(_) => println!("user table query succeed"),
                Err(_code) => {
                    errors.push(String::from("Invalid Username / Password".to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("login.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            
            match user_in_question_statement.next() {
                Ok(_res)=> {    
                    u = match user_in_question_statement.read::<String, _>("username") {
                        Ok(result) => result,
                        Err(_code) => {
                            errors.push(String::from("Invalid Username / Password"));
                            context.insert("errors", &errors);
                            let crap = match TEMPLATES.render("login.html", &context) {
                                Ok(cp) =>  cp,
                                Err(cp) => return MyResponse::Error(cp.to_string())
                            };
                            return MyResponse::Html(RawHtml(crap))
                        }
                    };
                    p = match user_in_question_statement.read::<String, _>("password"){
                        Ok(result) => result,
                        Err(_code) => {
                            errors.push(String::from("Invalid Username / Password"));
                            context.insert("errors", &errors);
                            let crap = match TEMPLATES.render("login.html", &context) {
                                Ok(cp) =>  cp,
                                Err(cp) => return MyResponse::Error(cp.to_string())
                            };
                            return MyResponse::Html(RawHtml(crap))
                        }
                    };
                    userid = match user_in_question_statement.read::<i64, _>("id"){
                        Ok(result) => result,
                        Err(_code) => {
                            errors.push(String::from("Invalid Username / Password"));
                            context.insert("errors", &errors);
                            let crap = match TEMPLATES.render("login.html", &context) {
                                Ok(cp) =>  cp,
                                Err(cp) => return MyResponse::Error(cp.to_string())
                            };
                            return MyResponse::Html(RawHtml(crap))
                        }
                    };

                    if u == "" {
                        errors.push(String::from("Invalid Username / Password"));
                        let crap = match TEMPLATES.render("login.html", &context){
                            Ok(result) => result,
                            Err(_code) => {
                                errors.push(String::from("Invalid Username / Password"));
                                context.insert("errors", &errors);
                                let crap = match TEMPLATES.render("login.html", &context) {
                                    Ok(cp) =>  cp,
                                    Err(cp) => return MyResponse::Error(cp.to_string())
                                };
                                return MyResponse::Html(RawHtml(crap))
                            }
                        };
                        return MyResponse::Html(RawHtml(crap));
                    }

                    if p == "" {
                        errors.push(String::from("Invalid Username / Password"));
                        let crap = match TEMPLATES.render("login.html", &context){
                            Ok(result) => result,
                            Err(_code) => {
                                errors.push(String::from("Invalid Username / Password"));
                                context.insert("errors", &errors);
                                let crap = match TEMPLATES.render("login.html", &context) {
                                    Ok(cp) =>  cp,
                                    Err(cp) => return MyResponse::Error(cp.to_string())
                                };
                                return MyResponse::Html(RawHtml(crap))
                            }
                        };
                        return MyResponse::Html(RawHtml(crap));
                    }
                    


                },
                Err(_) => {
                    errors.push("Invalid Username / Password".to_string());
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("login.html", &context){
                        Ok(result) => result,
                        Err(code) => {
                            errors.push(String::from(code.to_string()));
                            context.insert("errors", &errors);
                            let crap = match TEMPLATES.render("login.html", &context) {
                                Ok(cp) =>  cp,
                                Err(cp) => return MyResponse::Error(cp.to_string())
                            };
                            return MyResponse::Html(RawHtml(crap))
                        }
                    };
                    return MyResponse::Html(RawHtml(crap));
                }

            }
        },
        Err(_) => return MyResponse::Error("mutex lock failed".to_string())
    };

    match verify(password, &p) {
        Ok(res) => {
            if res {
                let expiration = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 60 * 60 * 24; // 24 hours

                let claims = Claims {
                    exp: expiration as usize,
                    sky_color: "Blue".to_string(),
                    userid: userid.try_into().expect("something wrong in userid"),
                    username: username.to_string(),
                };
                let jwtkey = match dotenv::var("JWTSECRET"){
                    Ok(result) => result,
                    Err(code) => {
                        errors.push(String::from(code.to_string()));
                        context.insert("errors", &errors);
                        let crap = match TEMPLATES.render("login.html", &context) {
                            Ok(cp) =>  cp,
                            Err(cp) => return MyResponse::Error(cp.to_string())
                        };
                        return MyResponse::Html(RawHtml(crap))
                    }
                };

                let header = jsonwebtoken::Header::default();
                let token = encode(&header, &claims, &EncodingKey::from_secret(jwtkey.as_bytes()))
                    .expect("Error creating jwt token");

                let mut cookie = Cookie::new("ourSimpleApp", token);
                cookie.set_http_only(true);  // Prevent JavaScript access to cookie
                cookie.set_secure(true);     // Only send over HTTPS
                cookie.set_same_site(SameSite::Strict); // Restrict cookie sending across sites
                cookie.set_max_age(Duration::hours(24));
                // let encoding_key = EncodingKey::from_secret(jwt_secret.0.as_bytes());
                jar.add(cookie);
                println!("password is right")
            } else {
                errors.push(String::from("Invalid Username / Password"));
                let crap = match TEMPLATES.render("login.html", &context){
                    Ok(result) => result,
                    Err(code) => {
                        errors.push(String::from(code.to_string()));
                        context.insert("errors", &errors);
                        let crap = match TEMPLATES.render("login.html", &context) {
                            Ok(cp) =>  cp,
                            Err(cp) => return MyResponse::Error(cp.to_string())
                        };
                        return MyResponse::Html(RawHtml(crap))
                    }
                };
                println!("password is wrong");
                return MyResponse::Html(RawHtml(crap));
            }
        },
        Err(err) => {
            errors.push(String::from(err.to_string()));
            let crap = match TEMPLATES.render("login.html", &context){
                Ok(result) => result,
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("login.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            println!("password is wrong");
            return MyResponse::Html(RawHtml(crap));
        }
    }
    MyResponse::Redirect(Redirect::to("/"))
}

#[post("/register", data = "<form>")]
pub fn register(state: &State<DbConn>, form: Form<LoginForm<'_>>, jar: &CookieJar<'_>) -> MyResponse {
    let mut errors: Vec<String> = Vec::new();
    let mut context = Context::new();
    let mut u = String::new();
    let mut p = String::new();

    let mut username: &str;
    let mut password: &str;

    let mut jwp_user_username = String::new();
    let mut jwp_user_password = String::new();
    let mut jwp_user_userid = 0;

    match state.conn.lock() {
        Ok(connection) => {
            let signin_form = form.into_inner();
            username = if signin_form.username.is_empty() {
                ""
            } else {
                signin_form.username
            };
            password = if signin_form.password.is_empty() {
                ""
            } else {
                signin_form.password
            };

            username = username.trim();
            password = password.trim();

            if username.len() > 32 {
                errors.push(String::from("The amount of characters in the name should not exceed 32"));
            }

            if password.len() > 32 {
                errors.push(String::from("The amount of characters in the password should not exceed 32"));
            }

            if username == "" {
                errors.push(String::from("Invalid Username / Password"));
            }

            if password == "" {
                errors.push(String::from("Invalid Username / Password"));
            }

            let re = Regex::new(r"/^[a-zA-Z0-9]+$/").unwrap();
            if re.is_match(username) {
                errors.push(String::from("regex failed"));
            }
            println!("username: {}\npassword: {}\n", username, password);
            if errors.len() > 0 {
                context.insert("errors", &errors);
                let crap = match TEMPLATES.render("homepage.html", &context) {
                    Ok(cp) =>  cp,
                    Err(cp) => return MyResponse::Error(cp.to_string())
                };
                return MyResponse::Html(RawHtml(crap))
            }

            let mut user_in_question_statement = match connection.prepare("SELECT * FROM users WHERE username = ?") {
                Ok(value) => value,
                Err(code) => {
                    eprintln!("{}",code.to_string());
                    errors.push(String::from("Invalid Username / Password".to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            match user_in_question_statement.bind((1, username)){
                Ok(_) => println!("user table query succeed"),
                Err(code) => {
                    eprintln!("{}", code.to_string());
                    errors.push(String::from("Invalid Username / Password".to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };

            match user_in_question_statement.next() {
                Ok(_res)=> {
                    u = match user_in_question_statement.read::<String, _>("username") {
                        Ok(result) => { println!("{}",result); result },
                        Err(code) => {
                            println!("expected behaviour");
                            "".to_string()
                        }
                    };

                },
                Err(code) => {
                    eprintln!("{}, err from user in question statement.next",code.to_string());
                    errors.push("Invalid Username / Password".to_string());
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("homepage.html", &context){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Error(code.to_string())

                        }
                    };
                    return MyResponse::Html(RawHtml(crap));
                }

            }

            if u == username {
                errors.push("Username is already taken".to_string());
                context.insert("errors", &errors);
                let crap = match TEMPLATES.render("homepage.html", &context){
                    Ok(result) => return MyResponse::Html(RawHtml(result)),
                    Err(code) => {
                        return MyResponse::Error(code.to_string())
                    }
                };
            }

        },
        Err(_) => return MyResponse::Error("mutex lock failed".to_string())
    };

    let plain_password = password.clone();


    match bcrypt::hash(plain_password, DEFAULT_COST) {
        Ok(hashed_password) => {
            match state.conn.lock() {
                Ok(connection) => {
                    let mut statement = match connection.prepare("INSERT INTO users (username, password) VALUES (?, ?)") {
                        Ok(value) => value,
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };
                    match statement.bind((1, username)){
                        Ok(_) => println!("user table query succeed"),
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };

                    match statement.bind((2, hashed_password.as_str())){
                        Ok(_) => println!("user table query succeed"),
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };
                    let mut last_inserted_row_id = 0;
                    match statement.next() {
                        Ok(_) => {
                            // Return a success response (e.g., redirect)
                            println!("updating user table query succeed");
                        }
                        Err(code) => {
                            return MyResponse::Error(code.to_string());
                        }
                    };

                    let mut statement = match connection.prepare("SELECT last_insert_rowid()") {
                        Ok(value) => value,
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };

                    match statement.next() {
                        Ok(_) => {
                            last_inserted_row_id = match statement.read::<i64, _>(0) {
                                Ok(row_id) => row_id,
                                Err(code) => { return MyResponse::Error(code.to_string()) }
                            };
                        }
                        Err(code) => {
                            return MyResponse::Error(code.to_string());
                        }
                    }

                    let mut statement = match connection.prepare("SELECT * FROM users where ROWID = ?") {
                        Ok(value) => value,
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };
                    match statement.bind((1, last_inserted_row_id)){
                        Ok(_) => println!("user table query succeed"),
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
                        }
                    };

                    match statement.next() {
                        Ok(_) => {
                            jwp_user_username = match statement.read::<String, _>("username") {
                                Ok(result) => result,
                                Err(_code) => {
                                    errors.push(String::from("Invalid Username / Password"));
                                    context.insert("errors", &errors);
                                    let crap = match TEMPLATES.render("login.html", &context) {
                                        Ok(cp) =>  cp,
                                        Err(cp) => return MyResponse::Error(cp.to_string())
                                    };
                                    return MyResponse::Html(RawHtml(crap))
                                }
                            };
                            jwp_user_password = match statement.read::<String, _>("password"){
                                Ok(result) => result,
                                Err(_code) => {
                                    errors.push(String::from("Invalid Username / Password"));
                                    context.insert("errors", &errors);
                                    let crap = match TEMPLATES.render("login.html", &context) {
                                        Ok(cp) =>  cp,
                                        Err(cp) => return MyResponse::Error(cp.to_string())
                                    };
                                    return MyResponse::Html(RawHtml(crap))
                                }
                            };
                            jwp_user_userid = match statement.read::<i64, _>("id"){
                                Ok(result) => result,
                                Err(_code) => {
                                    errors.push(String::from("Invalid Username / Password"));
                                    context.insert("errors", &errors);
                                    let crap = match TEMPLATES.render("login.html", &context) {
                                        Ok(cp) =>  cp,
                                        Err(cp) => return MyResponse::Error(cp.to_string())
                                    };
                                    return MyResponse::Html(RawHtml(crap))
                                }
                            };
                        }
                        Err(code) => {
                            return MyResponse::Error(code.to_string());
                        }
                    };
                }
                Err(_) => {
                    return MyResponse::Error("locking mutex failed".to_string());
                }
            }

            let expiration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60 * 60 * 24; // 24 hours

            let claims = Claims {
                exp: expiration as usize,
                sky_color: "Blue".to_string(),
                userid: jwp_user_userid.try_into().expect("something wrong in userid"),
                username: jwp_user_username.to_string(),
            };
            let jwtkey = match dotenv::var("JWTSECRET"){
                Ok(result) => result,
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("login.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };

            let header = jsonwebtoken::Header::default();
            let token = encode(&header, &claims, &EncodingKey::from_secret(jwtkey.as_bytes()))
                .expect("Error creating jwt token");

            let mut cookie = Cookie::new("ourSimpleApp", token);
            cookie.set_http_only(true);  // Prevent JavaScript access to cookie
            cookie.set_secure(true);     // Only send over HTTPS
            cookie.set_same_site(SameSite::Strict); // Restrict cookie sending across sites
            cookie.set_max_age(Duration::hours(24));
            // let encoding_key = EncodingKey::from_secret(jwt_secret.0.as_bytes());
            jar.add(cookie);

        },
        Err(err) => {
            errors.push(String::from(err.to_string()));
            let crap = match TEMPLATES.render("login.html", &context){
                Ok(result) => result,
                Err(code) => {
                    errors.push(String::from(code.to_string()));
                    context.insert("errors", &errors);
                    let crap = match TEMPLATES.render("login.html", &context) {
                        Ok(cp) =>  cp,
                        Err(cp) => return MyResponse::Error(cp.to_string())
                    };
                    return MyResponse::Html(RawHtml(crap))
                }
            };
            println!("password is wrong");
            return MyResponse::Html(RawHtml(crap));
        }
    }
    MyResponse::Redirect(Redirect::to("/"))
}

#[get("/logout")]
fn logout(user: OptionalUser, cookie_jar: &CookieJar<'_>) -> MyResponse {
    if let Some(user) = user.0 {
        cookie_jar.remove("ourSimpleApp");
        return MyResponse::Redirect(Redirect::to("/"))
    } else {
        return MyResponse::Html(RawHtml("You are not logged in.".to_string()));
    }
}

pub fn stage(conn: Connection) -> AdHoc {
    AdHoc::on_ignite("Managed Hit Count", |rocket| async {
        rocket.mount("/", routes![index, render_login, handle_login, logout, get_post, delete_post, create_post, handle_create_post,
                                              edit_post, handle_edit_post, register])
            .manage(DbConn {
                conn: Mutex::new(conn)
            })
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn testcookie() {
        let cc = rocket::http::Cookie::new("vale", "name");
        let ss = cc.to_string();
        assert_eq!(ss, "crap");
        
    }

    #[test]
    fn testdataquery() {
        let username = "soethiha";
        let connection = Connection::open("OurApp.db").expect("Failed to open database");
        let mut user_in_question_statement = connection.prepare("SELECT * FROM users WHERE USERNAME = ?").expect("something is wrong when checking user query");
        user_in_question_statement.bind((1, username)).expect("something is wrong in sql binding");

        while let Ok(sqlite::State::Row) = user_in_question_statement.next() {
            let u = user_in_question_statement.read::<String, _>("username").unwrap();
            let p = user_in_question_statement.read::<String, _>("password").unwrap();
            let userid = user_in_question_statement.read::<i64, _>("id").unwrap();
        if u == "" {
            panic!("user don't exist");
        }

        if p == "" {
            panic!("pass don't exist which is unlikely.");
            
        }

        println!("username = {}, password = {}, id = {}", u, p, userid);
    }
}
}
