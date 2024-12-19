// Backend (Node.js) with MongoDB and JWT for Authentication & Authorization

// Install required packages: express, mongoose, bcryptjs, jsonwebtoken, cors

const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')

const app = express()
const PORT = 5000
const JWT_SECRET = "your_jwt_secret_key"

// Middleware
app.use(express.json())
app.use(cors())

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/table_booking', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected')).catch((err) => console.error(err))

// MongoDB Models
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
})

const TableSchema = new mongoose.Schema({
    tableNumber: { type: Number, required: true, unique: true },
    seats: { type: Number, required: true },
    status: { type: String, enum: ['Available', 'Reserved'], default: 'Available' },
})

const ReservationSchema = new mongoose.Schema({
    tableId: { type: mongoose.Schema.Types.ObjectId, ref: 'Table', required: true },
    customerName: { type: String, required: true },
    date: { type: String, required: true },
    time: { type: String, required: true },
    status: { type: String, enum: ['Pending', 'Confirmed'], default: 'Pending' },
})

const User = mongoose.model('User', UserSchema)
const Table = mongoose.model('Table', TableSchema)
const Reservation = mongoose.model('Reservation', ReservationSchema)

// Routes

// User Registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) return res.status(400).json({ error: 'Missing username or password' })

    const hashedPassword = await bcrypt.hash(password, 10)

    try {
        const newUser = new User({ username, password: hashedPassword })
        await newUser.save()
        res.json({ message: 'User registered successfully' })
    } catch (err) {
        res.status(500).json({ error: 'User already exists' })
    }
})

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body

    const user = await User.findOne({ username })
    if (!user) return res.status(400).json({ error: 'Invalid credentials' })

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' })

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' })
    res.json({ token })
})

// Middleware to Authenticate JWT
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization

    if (!token) return res.status(403).json({ error: 'Access denied' })

    try {
        const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET)
        req.user = decoded
        next()
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' })
    }
}

// Add Table
app.post('/tables', authenticateJWT, async (req, res) => {
    const { tableNumber, seats } = req.body

    try {
        const newTable = new Table({ tableNumber, seats })
        await newTable.save()
        res.json({ message: 'Table added successfully' })
    } catch (err) {
        res.status(500).json({ error: 'Error adding table' })
    }
})

// Get Available Tables
app.get('/tables', async (req, res) => {
    const tables = await Table.find({ status: 'Available' })
    res.json(tables)
})

// Make a Reservation
app.post('/reservations', authenticateJWT, async (req, res) => {
    const { tableId, customerName, date, time } = req.body

    try {
        const table = await Table.findById(tableId)
        if (!table || table.status !== 'Available') return res.status(400).json({ error: 'Table not available' })

        table.status = 'Reserved'
        await table.save()

        const newReservation = new Reservation({ tableId, customerName, date, time, status: 'Confirmed' })
        await newReservation.save()

        res.json({ message: 'Reservation confirmed' })
    } catch (err) {
        res.status(500).json({ error: 'Error creating reservation' })
    }
})

app.listen(PORT, () => console.log(`Server running on port ${PORT}`))

