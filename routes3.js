const express = require("express");
const router = new express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/user");
const { SECRET_KEY } = require("../config");

// POST /login
// Login route
router.post("/login", async (req, res, next) => {
try {
const { username, password } = req.body;
const user = await User.authenticate(username, password);
if (user) {
const token = jwt.sign({ username: user.username }, SECRET_KEY);
await User.updateLoginTimestamp(username);
return res.json({ token });
} else {
throw new Error("Invalid username or password");
}
} catch (err) {
return next(err);
}
});

// POST /register
// Register route
router.post("/register", async (req, res, next) => {
try {
const { username, password, first_name, last_name, phone } = req.body;
const hashedPassword = await bcrypt.hash(password, 10);
const user = await User.register(
username,
hashedPassword,
first_name,
last_name,
phone
);
const token = jwt.sign({ username: user.username }, SECRET_KEY);
return res.json({ token });
} catch (err) {
return next(err);
}
});

module.exports = router;