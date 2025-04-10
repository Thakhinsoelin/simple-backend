#[macro_use] extern crate rocket;

use std::{sync::Mutex, time::{SystemTime, UNIX_EPOCH}};
use cookie::time::Duration;
use jsonwebtoken::{encode, EncodingKey};
use rocket::{http::{private::cookie, ContentType, Status}, response::Redirect};
use tera::{Context, Tera};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use rocket::{response::content::RawHtml,
    http::{Cookie, CookieJar, SameSite},
    State};
use rocket::fairing::AdHoc;
use rocket::form::Form;
use sqlite::{self, Connection};
use bcrypt::verify;

#[allow(non_snake_case)]
mod AppState;
use AppState::DbConn;

#[derive(FromForm, Deserialize)]
pub struct LoginForm<'r> {
    pub username: &'r str,
    pub password: &'r str,
}




// Simulated Posts
#[derive(Serialize, Deserialize)]
pub struct Post {
    id: u32,
    title: String,
    content: String,
    authorid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    sky_color: String,
    userid: i32,
    username: String,
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


#[get("/")]
pub fn index(state: &State<DbConn>) -> MyResponse {
    let mut context = Context::new();
    let _i = state.conn.lock().unwrap();
    // Simulate database query results.
    let _posts: Vec<Post> = vec![
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
            kind
        },
        Err(err) => {
            err.to_string()
        },
    };
    MyResponse::Html(RawHtml(crap))
    
}

#[get("/login")]
pub async fn render_login(_state: &State<DbConn>, /*jar: &CookieJar<'_>*/) -> MyResponse {
    let mut context = Context::new();
    let errors: Vec<String> = Vec::new();

    context.insert("errors", &errors);
    match TEMPLATES.render("login.html", &context) {
        Ok(result) => MyResponse::Html(RawHtml(result)),
        Err(err_code) => {
            MyResponse::Error(err_code.to_string())
        }
    }
}

// #[post("/login", data = "<form>")]
// pub fn handle_login(state: &State<DbConn>, form: Form<LoginForm<'_>>, jar: &CookieJar<'_>) -> MyResponse {
//     let mut errors: Vec<String> = Vec::new();
//     let connection = match state.conn.lock() {
//         Ok(connection) => {
//             let mut context = Context::new();
//             let loginform = form.into_inner();
//             let username = if loginform.username.is_empty() {
//                 "".to_string()
//             } else {
//                 loginform.username.to_string()
//             };
//             let password = if loginform.password.is_empty() {
//                 "".to_string()
//             } else {
//                 loginform.password.to_string()
//             };

//             let username = username.trim();
//             let password = password.trim();
//             if username == "" {
//                 errors.push(String::from("Invalid Username / Password"));
//             }

//             if password == "" {
//                 errors.push(String::from("Invalid Username / Password"));
//             }
//             println!("username: {}\npassword: {}\n", username, password);
//             if errors.len() > 0 {
//                 context.insert("errors", &errors);
//                 let crap = match TEMPLATES.render("login.html", &context) {
//                     Ok(cp) =>  cp,
//                     Err(cp) => return MyResponse::Error(cp.to_string())
//                 };
                
//             }

//             let mut user_in_question_statement = match connection.prepare("SELECT * FROM users WHERE USERNAME = ?") {
//                 Ok(value) => value,
//                 Err(code) => return MyResponse::Error(code.to_string())
//             };
//             match user_in_question_statement.bind((1, username)){
//                 Ok(_) => println!("user table query succeed"),
//                 Err(code) => return MyResponse::Error(code.to_string())
//             };

//             // let mut rows = match user_in_question_statement([]) { // No additional parameters needed for execution
//             //     Ok(rows) => rows,
//             //     Err(code) => return MyResponse::Error(code.to_string()),
//             // };

//             match user_in_question_statement.next() {
//                 Ok(bla)=> {    
//                     let u = match user_in_question_statement.read::<String, _>("username") {
//                         Ok(result) => result,
//                         Err(code) => return MyResponse::Error(code.to_string())
//                     };
//                     let p = match user_in_question_statement.read::<String, _>("password"){
//                         Ok(result) => result,
//                         Err(code) => return MyResponse::Error(code.to_string())
//                     };
//                     let userid = match user_in_question_statement.read::<i64, _>("id"){
//                         Ok(result) => result,
//                         Err(code) => return MyResponse::Error(code.to_string())
//                     };
//                     if u == "" {
//                         errors.push(String::from("Invalid Username / Password"));
//                         let crap = match TEMPLATES.render("login.html", &context){
//                             Ok(result) => result,
//                             Err(code) => return MyResponse::Error(code.to_string())
//                         };
//                         return MyResponse::Html(RawHtml(crap));
//                     }

//                     if p == "" {
//                         errors.push(String::from("Invalid Username / Password"));
//                         let crap = match TEMPLATES.render("login.html", &context){
//                             Ok(result) => result,
//                             Err(code) => return MyResponse::Error(code.to_string())
//                         };
//                         return MyResponse::Html(RawHtml(crap));
//                     }

//                     println!("from database:\nusername: {}\npassword: {}\n", u, p);
//                     match verify(password, &p) {
//                         Ok(_) => {
//                             let expiration = SystemTime::now()
//                             .duration_since(UNIX_EPOCH)
//                             .unwrap()
//                             .as_secs()
//                             + 60 * 60 * 24; // 24 hours

//                             let claims = Claims {
//                                 exp: expiration as usize,
//                                 skyColor: "Blue".to_string(),
//                                 userid: userid.try_into().expect("something wrong in userid"),
//                                 username: username.to_string(),
//                             };
//                             let jwtkey = match dotenv::var("JWTSECRET"){
//                                 Ok(result) => result,
//                                 Err(code) => return MyResponse::Error(code.to_string())
//                             };

//                             let header = jsonwebtoken::Header::default();
//                             let token = encode(&header, &claims, &EncodingKey::from_secret(jwtkey.as_bytes()))
//                                 .expect("Error creating jwt token");

//                             let mut cookie = Cookie::new("ourSimpleApp", token);
//                             cookie.set_http_only(true);  // Prevent JavaScript access to cookie
//                             cookie.set_secure(true);     // Only send over HTTPS
//                             cookie.set_same_site(SameSite::Strict); // Restrict cookie sending across sites
//                             cookie.set_max_age(Duration::hours(24));
//                             // let encoding_key = EncodingKey::from_secret(jwt_secret.0.as_bytes());
//                             jar.add(cookie);
//                             println!("password is right")
                            
//                         },
//                         Err(err) => {
//                             errors.push(String::from("Invalid Username / Password"));
//                             let crap = match TEMPLATES.render("login.html", &context){
//                                 Ok(result) => result,
//                                 Err(code) => return MyResponse::Error(code.to_string())
//                             };
//                             println!("password is wrong");
//                             return MyResponse::Html(RawHtml(crap));
//                         }
//                     }
//                 },
//                 Err(_) => {
//                     errors.push("Invalid Username / Password".to_string());
//                     let crap = match TEMPLATES.render("login.html", &context){
//                         Ok(result) => result,
//                         Err(code) => return MyResponse::Error(code.to_string())
//                     };
//                     return MyResponse::Html(RawHtml(crap));
//                 }

//             }

            

            
            
//         },
//         Err(_) => return MyResponse::Error("mutex lock failed".to_string())
//     };
//     MyResponse::Redirect(Redirect::to("/"))
// }

#[post("/login", data = "<form>")]
pub fn handle_login(state: &State<DbConn>, form: Form<LoginForm<'_>>, jar: &CookieJar<'_>) -> MyResponse {
    let mut errors: Vec<String> = Vec::new();
    let mut context = Context::new();
    match state.conn.lock() {
        Ok(connection) => {
            let loginform = form.into_inner();
            let username = if loginform.username.is_empty() {
                "".to_string()
            } else {
                loginform.username.to_string()
            };
            let password = if loginform.password.is_empty() {
                "".to_string()
            } else {
                loginform.password.to_string()
            };

            let username = username.trim();
            let password = password.trim();
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
                    let u = match user_in_question_statement.read::<String, _>("username") {
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
                    let p = match user_in_question_statement.read::<String, _>("password"){
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
                    let userid = match user_in_question_statement.read::<i64, _>("id"){
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

                    println!("from database:\nusername: {}\npassword: {}\n", u, p);
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
    MyResponse::Redirect(Redirect::to("/"))
}

pub fn stage(conn: Connection) -> AdHoc {
    AdHoc::on_ignite("Managed Hit Count", |rocket| async {
        rocket.mount("/", routes![index, render_login, handle_login])
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
