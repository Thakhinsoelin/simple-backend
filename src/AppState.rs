use std::sync::Mutex;

use sqlite::Connection;

pub struct DbConn(pub Mutex<Connection>);