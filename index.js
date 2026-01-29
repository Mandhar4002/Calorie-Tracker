import express from "express";
import bodyParser from "body-parser"; //Middleware for req.body
import pg from "pg" //Connecting to PostgreSQL
import bcrypt from "bcrypt"; //Hashing the password
import env from "dotenv"; //Storing sensitive information while project is being deployed
import session from "express-session"; //Session Tracking for cookies
import passport from "passport"; 
import { Strategy } from "passport-local"; //User authentication
import flash from "connect-flash"; //For incorrect login details message display

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    password: process.env.PG_PASSWORD,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    port: process.env.PG_PORT
});

db.connect();

app.get("/", (req, res) => {
    res.render("index.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs", {log : req.flash("error")});
});

app.get("/home", (req, res) => {
    if (req.isAuthenticated())
        res.render("home.ejs", { username: req.user.username });
    else
        res.redirect("/");
});

app.get("/bmi", (req, res) => {
    if (req.isAuthenticated())
        res.render("bmi.ejs", { username: req.user.username });
    else
        res.redirect("/");

});



app.get("/counter", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("counter.ejs", { username: req.user.username });
    }
    else
        res.redirect("/");
});

app.post("/counter", async (req, res) => {
    let query = req.body.query;

    //Str in Proper case conversion
    function toProperCase(str) {
        return str.toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase());
    }

    query = toProperCase(query);

    try {
        const checkResult = await db.query(`SELECT * FROM food_nutrition WHERE item_name = '${query}'`);

        //Checking for a food item
        if (checkResult.rowCount > 0) {
            const cal = Math.round(checkResult.rows[0].calories);

            let jog = Math.round(cal / 371 * 60);
            let walk = Math.round(cal / 294 * 60);
            let weight = Math.round(cal / 484 * 60);
            let yoga = Math.round(cal / 223 * 60);

            res.render("counter.ejs", {username: req.user.username, 
                                        item_name: checkResult.rows[0].item_name,
                                        calories: cal,
                                        carbohydrates: checkResult.rows[0].carbohydrates,
                                        cholesterol: checkResult.rows[0].cholesterol,
                                        saturated_fat: checkResult.rows[0].saturated_fat,
                                        total_fat: checkResult.rows[0].total_fat,
                                        fiber_content: checkResult.rows[0].fiber_content,
                                        potassium: checkResult.rows[0].potassium,
                                        protein: checkResult.rows[0].protein,
                                        sodium: checkResult.rows[0].sodium,
                                        sugar: checkResult.rows[0].sugar,
                                        jog : jog,
                                        walk : walk,
                                        weight : weight,
                                        yoga : yoga
            });
        }
        else {
            res.render("counter.ejs", {err : "Item doesn't exist", username: req.user.username});
        }

    }
    catch(error) {
        res.render("index.ejs", {err : "Something went wrong"});
    }
});

app.get("/bmr", (req, res) => {
    if (req.isAuthenticated())
        res.render("bmr.ejs", { username: req.user.username });
    else
        res.redirect("/");
});

app.get("/about", (req, res) => {
    if (req.isAuthenticated())
        res.render("about.ejs", { username: req.user.username });
    else
        res.redirect("/");
});

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.render("index.ejs", { log: "Logged Out Successfully" });
    });
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/login",
    failureFlash: true
}));

app.post("/register", async (req, res) => {
    const user = req.body.name;
    const email = req.body.username;
    const password = req.body.password;

    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

        if (checkResult.rows.length > 0) {
            res.render("login.ejs", { log: "Email already exists. Try logging in." });
        } else {
            //hashing the password and saving it in the database
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    console.log("Hashed Password:", hash);
                    const result = await db.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *", [user, email, hash]);

                    const currUser = result.rows[0];
                    req.login(currUser, (err) => {
                        console.log("Success");
                        res.render("home.ejs", { username: user });
                    });
                }
            });
        }
    }
    catch (err) {
        console.log(err);
    }
});

passport.use(new Strategy(async function verify(username, password, cb) {
    try {
        const result = await db.query("SELECT * FROM USERS WHERE EMAIL = $1", [username]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const storedHashedPassword = user.password;
            //verifying the password
            bcrypt.compare(password, storedHashedPassword, (err, valid) => {
                if (err) {
                    console.error("Error comparing passwords:", err);
                    return cb(err);
                } else {
                    if (valid) {
                        return cb(null, user);
                    } else {
                        return cb(null, false, { message: "Invalid Username or Password." });
                    }
                }
            });
        }
        else {
            return cb(null, false, { message: "Invalid Username or Password." });
        }
    } catch (error) {
        console.log(error);
    }
}));

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(port, () => {
    console.log(`Server is listening on ${port}`);
});