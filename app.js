const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');
const cors = require('cors')
require('dotenv').config();

const app = express();


// cors
app.use(cors())

// Middleware
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);

// Connect to MongoDB without deprecated options
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('MongoDB Connected...');
    })
    .catch((err) => {
        console.error('MongoDB connection error:', err.message);
    });

module.exports = app;
