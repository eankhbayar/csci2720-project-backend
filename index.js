const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const fs = require('fs');
const cors = require('cors');
var parser = require('xml2json');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'pZd6pmFzw2BO39+N9r+DmwKx0QlZBuXaivHxT2L4nKU='; // Replace with a secure key in production
app.use(bodyParser.json());
app.use(cors());

mongoose.connect('mongodb://localhost:27017/project');

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error:'));

db.once('open', () => {
	console.log('MongoDB connected');
});

const userSchema = new mongoose.Schema({
	username: { type: String, required: true, unique: true },
	password: { type: String, required: true },
	role: { type: String, default: 'user' }, // 'user' or 'admin'
});

const User = mongoose.model('User', userSchema);

// Location schema
const locationSchema = new mongoose.Schema({
	id: String,
	locationname: String,
	latitude: Number,
	longitude: Number,
});

const Location = mongoose.model('Location', locationSchema);

// Event schema
const eventSchema = new mongoose.Schema({
	title: String,
	venue: String,
	datetime: String,
	description: String,
	presenter: String,
});

const Event = mongoose.model('Event', eventSchema);

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

// Reset database and initialize data
const initializeData = async () => {
	await Location.deleteMany({});
	await Event.deleteMany({});

	let locationIds = [];

	fs.readFile('./venues.xml', async (err, data) => {
		if (err) throw err;
		const json = JSON.parse(parser.toJson(data));
		const venues = json.venues.venue;

		const locations = venues.map((venue) => ({
			id: venue.id,
			locationname: venue.venuee,
			latitude: parseFloat(venue.latitude) || 0,
			longitude: parseFloat(venue.longitude) || 0,
		}));

		locationIds = locations.map((location) => location.id);

		await Location.insertMany(locations);
		console.log('Locations initialized');
	});

	fs.readFile('./events.xml', async (err, data) => {
		if (err) throw err;
		const json = JSON.parse(parser.toJson(data));
		const events = json.events.event;

		const eventList = events
        .filter(event => locationIds.includes(event.venueid) && !(typeof event.desce === 'object' && Object.keys(event.desce).length === 0))
        .map((event) => {
            return {
                id: event.id,
                title: event.titlee,
                venue: event.venueid,
                datetime: event.predateE,
                description: event.desce,
                presenter: event.presenterorge,
            };
        });

		await Event.insertMany(eventList);
		console.log('Events initialized');
	});
};

initializeData();

app.get('/locations', authenticateToken, async (req, res) => {
	const locations = await Location.find({});
	res.json(locations);
});

app.get('/events', authenticateToken, async (req, res) => {
	const events = await Event.find({});
	res.json(events);
});

app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
});
