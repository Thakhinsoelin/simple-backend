// 2:00:51

require("dotenv").config()
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cookieP = require("cookie-parser")
const express = require("express");
const sanitize = require("sanitize-html")
const db = require("better-sqlite3")("OurApp.db")
db.pragma("journal_mode = WAL")

// database setup here

const createTables = db.transaction(() => {
    db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )    
    `
    ).run()  

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
        )
        `
    ).run();
})

createTables()

// database ends here

const app = express()

app.set("view engine" , "ejs");
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(cookieP())


app.use(function (req, res, next) {
    res.locals.error = []

    //try to decode incoming cookie
    try {
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    } catch (error) {
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)
    next()
})


app.get("/", (req, res) => {
    if(req.user) {
        const getPostStatement = db.prepare("SELECT * FROM posts WHERE authorid = ?")
        const posts = getPostStatement.all(req.user.userid)
        return res.render("dashboard", {posts})
    }

    res.render("homepage")
})

app.get("/login", (req,res) => {
    res.render("login")
})

app.post("/login", (req,res) => {
    let error = []

    if(typeof req.body.username !== "string") {
        req.body.username = ""
    }
    if(typeof req.body.password !== "string") {
        req.body.password = ""
    }    

    if (req.body.username.trim() == "") error = ["Invalid Username / Password"]
    if (req.body.password == "") error = ["Invalid Username / Password"]

    if(error.length) {
        return res.render("login", {error})
    }
    
    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    if(!userInQuestion) {
        error = ["Invalid username / password"]
        return res.render("login", {error})
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if(!matchOrNot) {
        error = ["Invalid username / password"]
        return res.render("login", {error})
    }

    // give them a cookie and redirect
    const ourTokenValue = jwt.sign (
        {exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "Blue", userid: userInQuestion.id, username: userInQuestion.username}, 
        process.env.JWTSECRET
    )

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/")
})

let mustBeLoggedIn = (req, res, next) => {
    if(req.user) {
        return next()
    }

    return res.redirect("/")
}

app.get("/logout", (req,res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.get("/create-post", mustBeLoggedIn, (req,res) => {
    res.render("create-post")
})

const sharedPostValidation = (req) => {
    const errors = []

    if(typeof req.body.title !== "string") req.body.title = ""
    if(typeof req.body.body !== "string") req.body.body = ""

    //trim - sanitize or strip out html
    req.body.title = sanitize(req.body.title.trim(), {
        allowedTags: [],
        allowedAttributes: {},
    })

    req.body.body = sanitize(req.body.body.trim(), {
        allowedTags: [],
        allowedAttributes: {},
    })

    if(!req.body.title ) errors.push("You must provide a title.")
    if(!req.body.body ) errors.push("You must provide a title.")

    return errors   
}

app.get("/edit-post/:id", mustBeLoggedIn, (req,res) => {
    // try to look up the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    if(!post) res.redirect("/")
    // if you're not the author, redirect to homepage
    if(post.authorid !== req.user.userid) {
        return res.redirect("/")
    }
    // otherwise render the edit post template
    res.render("edit-post", {post})
})

app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    if(!post) res.redirect("/")
    // if you're not the author, redirect to homepage
    if(post.authorid !== req.user.userid) {
        return res.redirect("/")
    }

    const errrors = sharedPostValidation(req)
    if(errrors.length) {
        return res.render("edit-post", {errrors})
    }

    const updateStatement = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")
    updateStatement.run(req.body.title, req.body.body, req.params.id)

    return res.redirect(`/post/${req.params.id}`)
})

app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    if(!post) res.redirect("/")
    // if you're not the author, redirect to homepage
    if(post.authorid !== req.user.userid) {
        return res.redirect("/")
    }

    const deleteStatement = db.prepare("DELETE FROM posts WHERE id = ?")
    deleteStatement.run(req.params.id)

    res.redirect("/")
})

app.get("/post/:id", (req,res) => {
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statement.get(req.params.id)
    if(!post) {
        return res.redirect("/")
    }
    res.render("single-post", {post})

})

app.get("/test", (req,res) => {
    res.render("test")
})

app.post("/create-post", mustBeLoggedIn, (req,res) => {
    const errors = sharedPostValidation(req);

    if(errors.length) {
        return res.render("create-post", {errors})
    }

    // save it to database
    const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?) ")
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString())

    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
    const realPost = getPostStatement.get(result.lastInsertRowid)



    res.redirect(`/post/${realPost.id}`)
})

app.post("/register", (req, res) => {
    const error = []

    if(typeof req.body.username !== "string") {
        req.body.username = ""
    }
    if(typeof req.body.password !== "string") {
        req.body.password = ""
    }
    req.body.username = req.body.username.trim()

    
    if(!req.body.username) error.push("You must provide a username")
    if(req.body.username && req.body.username.length < 3) error.push("Username must have at least three characters")
    if(req.body.username && req.body.username.length > 10) error.push("Username should not longer than three characters")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) error.push("Username can contain only letters or numbers")

    // check if username exist already
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameStatement.get(req.body.username)
    if(usernameCheck){
        error.push("That username is already taken")
    }

    if(!req.body.password) error.push("You must provide a password")
    if(req.body.password && req.body.password.length < 8) error.push("Password must have at least 八 characters")
    if(req.body.password && req.body.password.length > 70) error.push("Password should not longer than 七十 characters")

    if (error.length) {
        return res.render("homepage", {error})
    }

    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    // save the username into database
    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    const result = ourStatement.run(req.body.username, req.body.password)

    const lookupstatement = db.prepare("SELECT * FROM users where ROWID = ?")
    const ourUser = lookupstatement.get(result.lastInsertRowid)
    // log the user in by giving them a cookie
    const ourTokenValue = jwt.sign ({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "Blue", userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)
    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.redirect("/")
})


app.listen(3000)