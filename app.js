import express from 'express'
import dotenv from 'dotenv'
import dbconn from './db/config.js';
import path from 'path';
import bcrypt from 'bcrypt'
import userModel from './model/user.js';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config()
dbconn()

const app = express();
app.use(cookieParser())
app.set('view engine', 'ejs');
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

const authenticate = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect("/")
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, decode) => {
        if (err) {
            res.redirect("/")
        }
        req.user = decode;
        next();
    })
}

app.get('/', (req, res) => {
    if (req.cookies.token) {
        res.redirect('/home')
    }
    res.render("index");
})

app.get('/register', (req, res) => {
    if (req.cookies.token) {
        res.redirect('/home')
    }
    res.render("register", { msg: "" });
})

app.get('/login', (req, res) => {
    if (req.cookies.token) {
        res.redirect('/home')
    }
    res.render("login", { msg: "" });
})
app.get('/home', authenticate, async (req, res) => {
    const user = await userModel.findOne({ email: req.user.email })
    res.render("home", { user });
})
app.get('/logout', (req, res) => {
    res.clearCookie("token");
    res.redirect('/')
})
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.render('login', { msg: "Please fill out all required fields." })
    }
    const user = await userModel.findOne({ email });
    if (!user) {
        return res.render('login', { msg: "Invalid Credentials." })
    }
    const isValid = bcrypt.compare(password, user.password);
    if (!isValid) {
        return res.render('login', { msg: "Invalid Credentials." })
    }
    const token = jwt.sign({ email: user.email, userId: user._id }, process.env.JWT_SECRET);
    res.cookie("token", token);
    res.redirect('/home');
})

app.post('/register', async (req, res) => {
    const { fullname, email, mobile, age, password } = req.body;

    // Check for required fields
    if (!fullname || !email || !mobile || !age || !password) {
        return res.render("register", { msg: "Please fill out all required fields" });
    }

    // Check password length
    if (password.length < 6) {
        return res.render('register', { msg: "Password must be at least 6 characters long" });
    }

    // Check if user already exists
    const user = await userModel.findOne({ email });
    if (user) {
        return res.render('register', { msg: "User already exists" });
    }

    // Hash the password
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        // Create new user
        const createdUser = await userModel.create({
            fullname, email, mobile, age, password: hash
        });

        // Render success message
        return res.render('login', { msg: "Account Created Successfully" });
    } catch (err) {
        console.error(err);
        return res.render('register', { msg: "Internal server error. Please try again later." });
    }
});


app.listen(process.env.PORT, () => {
    console.log(`Server started on ${process.env.PORT}`);
})