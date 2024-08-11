require('dotenv').config(); // Add this at the top

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const MONGO_URI = process.env.MONGO_URI;

app.use(bodyParser.json());
app.use(cors());

let db;

// Connect to MongoDB
MongoClient.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    db = client.db('authdb');
    console.log('Connected to MongoDB');
  })
  .catch(error => console.error(error));

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const usersCollection = db.collection('users');
    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = bcrypt.hashSync(password, 8);
    await usersCollection.insertOne({ username, password: hashedPassword });
    res.status(201).json({ message: 'User registered' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Protected endpoint example
app.get('/protected', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Token missing' });
  }
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    res.json({ message: 'Protected resource accessed', user });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
