const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const fs = require('fs');
var parser = require('xml2json');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'pZd6pmFzw2BO39+N9r+DmwKx0QlZBuXaivHxT2L4nKU='; // Replace with a secure key in production
app.use(bodyParser.json());

fs.readFile('./events.xml', function(err, data) {
	var json = parser.toJson(data);
	console.log("to json ->", json);
});

fs.readFile('./venues.xml', function(err, data) {
	var json = parser.toJson(data);
	console.log("to json ->", json);
});

fs.readFile('./holiday.xml', function(err, data) {
	var json = parser.toJson(data);
	console.log("to json ->", json);
});

fs.readFile('./eventDates.xml', function(err, data) {
	var json = parser.toJson(data);
	console.log("to json ->", json);
});

mongoose.connect('mongodb://localhost:27017/authdb');

const userSchema = new mongoose.Schema({
	username: { type: String, required: true, unique: true },
	password: { type: String, required: true },
	role: { type: String, default: 'user' }, // 'user' or 'admin'
});

const User = mongoose.model('User', userSchema);

const generateToken = (user) => {
	return jwt.sign(
		{ id: user._id, username: user.username, role: user.role },
		JWT_SECRET,
		{ expiresIn: '1h' }
	);
};

// Routes

// Register
app.post('/register', async (req, res) => {
	const { username, password, role } = req.body;

	if (!username || !password) {
		return res.status(400).json({ message: 'Username and password are required.' });
	}

	const hashedPassword = await bcrypt.hash(password, 10);

	try {
		const newUser = new User({ username, password: hashedPassword, role });
		await newUser.save();
		res.status(201).json({ message: 'User registered successfully.' });
	} catch (error) {
		res.status(500).json({ message: 'Error registering user.', error });
	}
});

// Login
app.post('/login', async (req, res) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res.status(400).json({ message: 'Username and password are required.' });
	}

	try {
		const user = await User.findOne({ username });
		if (!user) {
			return res.status(404).json({ message: 'User not found.' });
		}

		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) {
			return res.status(401).json({ message: 'Invalid credentials.' });
		}

		const token = generateToken(user);
		res.json({ token });
	} catch (error) {
		res.status(500).json({ message: 'Error logging in.', error });
	}
});

// Middleware to Validate JWT
const authenticateToken = (req, res, next) => {
	const token = req.headers['authorization'];
	if (!token) {
		return res.status(403).json({ message: 'Token is required.' });
	}

	jwt.verify(token, JWT_SECRET, (err, user) => {
		if (err) {
			return res.status(403).json({ message: 'Invalid or expired token.' });
		}
		req.user = user;
		next();
	});
};

// Protected Route Example
app.get('/protected', authenticateToken, (req, res) => {
	res.json({ message: 'This is a protected route.', user: req.user });
});

app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
});
