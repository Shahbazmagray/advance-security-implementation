const express = require('express');
const app = express();

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const validator = require('validator');
app.use(express.json());

/* =========================
   WINSTON LOGGER SETUP
========================= */
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

/* =========================
   SAMPLE USER (for demo)
========================= */
let users = [
    {
        email: "test@gmail.com",
        password: bcrypt.hashSync("123456", 10)
    }
];

/* =========================
   LOGIN ROUTE
========================= */
app.post('/login', async (req, res) => {

    const { email, password } = req.body;

    // log every login attempt
    logger.info(`Login attempt from ${email}`);

    const user = users.find(u => u.email === email);

    if (!user) {
        logger.warn(`Failed login attempt (user not found): ${email}`);
        return res.status(400).send("User not found");
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
        logger.warn(`Failed login attempt (wrong password): ${email}`);
        return res.status(400).send("Invalid password");
    }

    // SUCCESS LOG (THIS IS YOUR LINE)
    logger.info(`Successful login for ${email}`);

    const token = jwt.sign(
        { email: user.email },
        "secretkey",
        { expiresIn: "1h" }
    );

    res.json({
        message: "Login successful",
        token: token
    });
});


// Signup Route
app.post('/signup', async (req, res) => {

    const { email, password } = req.body;

    // Validate Email
    if (!validator.isEmail(email)) {
        return res.status(400).send('Invalid email');
    }

    // Validate Password Length
    if (!validator.isLength(password, { min: 6 })) {
        return res.status(400).send('Password must be at least 6 characters');
    }

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save User
    users.push({
        email,
        password: hashedPassword
    });

    res.send('User registered successfully');
});

/* =========================
   START SERVER
========================= */
app.listen(3000, () => {
    logger.info("Application started");
    console.log("Server running on http://localhost:3000");
});
