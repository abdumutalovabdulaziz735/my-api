const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const adapter = new FileSync('db.json');
const db = low(adapter);

const app = express();
const SECRET = 'mysecretkey123';

app.use(cors());
app.use(express.json());

app.get('/api/v1/products', (req, res) => {
    const products = db.get('products').value();
    const ordering = req.query.ordering;
    
    let sorted = [...products];
    if (ordering === 'title') sorted.sort((a, b) => a.title.localeCompare(b.title));
    if (ordering === 'price') sorted.sort((a, b) => parseFloat(a.price) - parseFloat(b.price));
    if (ordering === 'rating') sorted.sort((a, b) => b.rating - a.rating);

    res.json({
        count: sorted.length,
        next: null,
        previous: null,
        results: sorted
    });
});

app.post('/api/v1/auth/register', async (req, res) => {
    const { username, email, password, password2 } = req.body;

    if (!username || !email || !password || !password2) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (password !== password2) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    const existingUser = db.get('users').find({ username }).value();
    if (existingUser) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: Date.now(),
        username,
        email,
        password: hashedPassword
    };

    db.get('users').push(newUser).write();
    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/v1/auth/login', async (req, res) => {
    const { username, password } = req.body;

    const user = db.get('users').find({ username }).value();
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }

    const access = jwt.sign({ id: user.id, username }, SECRET, { expiresIn: '3d' });
    const refresh = jwt.sign({ id: user.id }, SECRET, { expiresIn: '7d' });

    res.json({ access, refresh, user: { id: user.id, username, email: user.email } });
});

app.get('/api/v1/users', (req, res) => {
    const users = db.get('users').value();
    const safeUsers = users.map(({ password, ...rest }) => rest);
    res.json({
        count: safeUsers.length,
        results: safeUsers
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
