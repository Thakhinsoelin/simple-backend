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
use rocket::form::Form;
use sqlite::{self, Connection};
use bcrypt::verify;
use std::option::Option;
#[allow(non_snake_case)]
mod AppState;
use AppState::DbConn;

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
                            return MyResponse::Error(code.to_string())
                        }
                    };
                    post_created_date = match statement.read::<String, _>("createdDate"){
                        Ok(result) => result,
                        Err(code) => {
                            return MyResponse::Error(code.to_string())
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
    match user.0 {
        Some(user) => {
            context.insert("user", &user);
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

fn shared_post_validation() -> Vec<String> {

}

#[post("/create-post", data = "<post>")]
fn handle_create_post(user: OptionalUser, state: &State<DbConn>, post: Form<PostForm<'_>>) -> MyResponse {

    todo!()
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
        rocket.mount("/", routes![index, render_login, handle_login, logout, get_post, delete_post, create_post, handle_create_post])
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
