// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// In-memory user storage
const users = [];

// Registration route
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
        return res.status(400).json({ message: 'Email already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, email, password: hashedPassword });

    return res.status(201).json({ message: 'User registered successfully.' });
});

// Login route
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = users.find(u => u.email === email);
    if (!user) {
        return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    return res.status(200).json({ message: 'Login successful.', token });
});

// Middleware to authenticate JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
}

// Protected profile route
app.get('/api/profile', authenticateToken, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}!`, email: req.user.email });
});

// Default route
app.get('/', (req, res) => {
    res.send('Authentication API is running!');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
