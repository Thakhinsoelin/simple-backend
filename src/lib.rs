#[macro_use] extern crate rocket;

use std::{sync::Mutex, time::{SystemTime, UNIX_EPOCH}};
use cookie::time::Duration;
use jsonwebtoken::{encode, EncodingKey};
use rocket::{error, http::{private::cookie, Header, Status}, response::Redirect};
use tera::{Context, Tera};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use rocket::{response::content::RawHtml,
    http::{Cookie, CookieJar, SameSite},
    State};
use rocket::fairing::AdHoc;
use rocket::form::{validate, Form, ValueField};
use dotenv::dotenv;
use sqlite::{self, Connection};
use bcrypt::{hash, verify, DEFAULT_COST};

#[allow(non_snake_case)]
mod AppState;
use AppState::DbConn;

#[derive(FromForm, Deserialize)]
pub struct LoginForm<'r> {
    pub username: &'r str,
    pub password: &'r str,
}

#[derive(FromForm, Deserialize)]
pub struct ValidUsername<'r>(&'r str);

#[derive(FromForm, Deserialize)]
pub struct ValidPassword<'r>(&'r str);


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
    skyColor: String,
    userid: i32,
    username: String,
}

struct JwtSecret(String);

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
pub async fn index(state: &State<DbConn>) -> Result<RawHtml<String>, String> {
    let mut context = Context::new();
    let i = state.conn.lock().unwrap();
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
pub async fn render_login(state: &State<DbConn>, /*jar: &CookieJar<'_>*/) -> Result<RawHtml<String>, String> {
    // {let expiration = SystemTime::now()
    //     .duration_since(UNIX_EPOCH)
    //     .unwrap()
    //     .as_secs()
    //     + 60 * 60 * 24; // 24 hours

    //     let claims = Claims {
    //         exp: expiration as usize,
    //         skyColor: "Blue".to_string(),
    //         userid: 7,
    //         username: "soethiha".to_owned(),
    //     };
    //     let jwtkey = dotenv::var("JWTSECRET").map_err(|err| err.to_string())?;
    //     let header = jsonwebtoken::Header::default();
    //     // let header = Header::new(Default, Default);
    //     let token = encode(&header, &claims, &EncodingKey::from_secret(jwtkey.as_bytes()))
    //         .expect("Error creating jwt token");
    //     let mut cookie = Cookie::new("ourSimpleApp", token);
    //     cookie.set_http_only(true);  // Prevent JavaScript access to cookie
    //     cookie.set_secure(false);     // Only send over HTTPS
    //     cookie.set_same_site(SameSite::Strict); // Restrict cookie sending across sites
    //     cookie.set_max_age(Duration::hours(24));
    //     // let encoding_key = EncodingKey::from_secret(jwt_secret.0.as_bytes());
        
    // jar.add(cookie);}
    Redirect::to("/login");
    let mut context = Context::new();
    let errors: Vec<String> = Vec::new();

    context.insert("errors", &errors);
    let crap = TEMPLATES.render("login.html", &context).map_err(|err| err.to_string())?;
    Ok(RawHtml(crap))
}

#[post("/login", data = "<form>")]
pub fn handle_login(state: &State<DbConn>, form: Form<LoginForm<'_>>, jar: &CookieJar<'_>) -> Result<RawHtml<String>, String> {
    let connection = state.conn.lock().map_err(|err| err.to_string())?;
    let mut context = Context::new();
    let mut errors: Vec<String> = Vec::new();
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

    if errors.len() > 0 {
        context.insert("errors", &errors);
        let crap = TEMPLATES.render("login.html", &context).map_err(|err| err.to_string())?;
        return Ok(RawHtml(crap));
    }

    let mut userInQuestionStatement = connection.prepare("SELECT * FROM users WHERE USERNAME = ?").map_err(|err| err.to_string())?;
    userInQuestionStatement.bind((1, username)).map_err(|err| err.to_string())?;

    while let Ok(sqlite::State::Row) = userInQuestionStatement.next() {
        let u = userInQuestionStatement.read::<String, _>("username").map_err(|err| err.to_string())?;
        let p = userInQuestionStatement.read::<String, _>("password").map_err(|err| err.to_string())?;
        let userid = userInQuestionStatement.read::<i64, _>("id").map_err(|err| err.to_string())?;
        if u == "" {
            errors.push(String::from("Invalid Username / Password"));
            let crap = TEMPLATES.render("login.html", &context).map_err(|err| err.to_string())?;
            return Ok(RawHtml(crap));
        }

        if p == "" {
            errors.push(String::from("Invalid Username / Password"));
            let crap = TEMPLATES.render("login.html", &context).map_err(|err| err.to_string())?;
            return Ok(RawHtml(crap));
        }
        match verify(password, &p) {
            Ok(_) => {
                let expiration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60 * 60 * 24; // 24 hours

                let claims = Claims {
                    exp: expiration as usize,
                    skyColor: "Blue".to_string(),
                    userid: userid.try_into().expect("something wrong in userid"),
                    username: username.to_string(),
                };
                let jwtkey = dotenv::var("JWTSECRET").map_err(|err| err.to_string())?;
                let header = jsonwebtoken::Header::default();
                // let header = Header::new(Default, Default);
                let token = encode(&header, &claims, &EncodingKey::from_secret(jwtkey.as_bytes()))
                    .expect("Error creating jwt token");
                let mut cookie = Cookie::new("ourSimpleApp", token);
                cookie.set_http_only(true);  // Prevent JavaScript access to cookie
                cookie.set_secure(true);     // Only send over HTTPS
                cookie.set_same_site(SameSite::Strict); // Restrict cookie sending across sites
                cookie.set_max_age(Duration::hours(24));
                // let encoding_key = EncodingKey::from_secret(jwt_secret.0.as_bytes());
                jar.add(cookie);
                return Redirect::to(uri!(index));
                
            },
            Err(err) => {
                errors.push(String::from("Invalid Username / Password"));
                let crap = TEMPLATES.render("login.html", &context).map_err(|err| err.to_string())?;
                return Ok(RawHtml(crap));
            }
        }

    }
    
    Ok(RawHtml("Looks like login func works".to_string()))

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
        let mut userInQuestionStatement = connection.prepare("SELECT * FROM users WHERE USERNAME = ?").expect("something is wrong when checking user query");
        userInQuestionStatement.bind((1, username)).expect("something is wrong in sql binding");

        while let Ok(sqlite::State::Row) = userInQuestionStatement.next() {
            let u = userInQuestionStatement.read::<String, _>("username").unwrap();
            let p = userInQuestionStatement.read::<String, _>("password").unwrap();
            let userid = userInQuestionStatement.read::<i64, _>("id").unwrap();
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
