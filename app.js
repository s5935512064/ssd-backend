var express = require('express')
var bodyParser = require('body-parser')
var cors = require('cors')
var app = express()
var jsonParser = bodyParser.json()
var bcrypt = require('bcrypt');
var cookie = require('cookie');
var saltRounds = 10;
var jwt = require('jsonwebtoken');
const SECRET = "ssd_residence";
const router = require("express").Router();

app.use("/api", router);
router.use(cors({ origin: "http://localhost:3000", credentials: true }));
// router.use(cors())
router.use(express.json());
router.use(express.urlencoded({ extended: false }));

const mysql = require('mysql2');
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'ssd_residence'
});


router.post('/register', jsonParser, function (req, res, next) {
    const { username, email, password, fName, lName } = req.body;
    if (!username || !email || !password)
        return res.json({ message: "Cannot register with empty string" });

    connection.query(
        'SELECT * FROM user WHERE username = ?',
        [username],
        function (err, results) {
            if (err) {
                res.json({ status: "error", message: err })
                return
            } else {
                if (results.length)
                    return res.json({ message: "Duplicated user" });
                else {
                    bcrypt.hash(password, saltRounds, function (err, hash) {
                        connection.execute(
                            'INSERT INTO user (username, password, email, fName, lName) VALUES (?, ?, ?, ?, ?) ',
                            [username, hash, email, fName, lName],
                            function (err, results, fields) {
                                if (err) {
                                    res.json({ status: "error", message: err })
                                    return
                                }
                                res.status(200).json({ message: "Register success" });
                            }
                        )
                    });
                }
            }
        }
    );
})

router.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM user WHERE username=?',
        [req.body.username],
        function (err, results, fields) {
            if (err) return next(err);

            if (results == 0) {
                return res.json({ status: "User Not Found" })
            }

            bcrypt.compare(req.body.password, results[0].password, function (err, isLogin) {
                if (isLogin) {

                    var token = jwt.sign({ username: results[0].username, fName: results[0].fName, lName: results[0].lName }, SECRET, {
                        expiresIn: "1d"
                        // expiresIn: req.body.ischeck === "on" ? "7d" : "1d",
                    });
                    res.setHeader(
                        "Set-Cookie",
                        cookie.serialize("token", token, {
                            httpOnly: true,
                            secure: process.env.NODE_ENV !== "development",
                            maxAge: 60 * 60,
                            sameSite: "strict",
                            path: "/",
                        })
                    );
                    return res.json({ status: "Login Success", token, isLogin })
                } else {
                    return res.json({ status: "Wrong password" })
                }
            });
        }
    )
});

router.get("/logout", jsonParser, (req, res) => {
    res.setHeader(
        "Set-Cookie",
        cookie.serialize("token", "", {
            httpOnly: true,
            secure: process.env.NODE_ENV !== "development",
            maxAge: -1,
            sameSite: "strict",
            path: "/",
        })
    );
    res.statusCode = 200;
    return res.json({ message: "Logout successful" });
});



router.get("/alluser", (req, res) => {
    connection.query(
        'SELECT * FROM user',
        function (err, results, fields) {
            if (err) {
                res.json({ status: "error", message: err })
                return
            }
            return res.json(results)
        }
    )
});


app.listen(3333, function () {
    console.log('CORS-enabled web server listening on port 3333')
})