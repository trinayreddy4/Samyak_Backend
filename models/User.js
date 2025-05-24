const mongoose = require('mongoose');

// Define User Schema
const UserSchema = new mongoose.Schema({
    firstname: {
        type: String,
        required: true,
    },
    lastname: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    phoneNumber: {
        type: String,
        required: true,
        unique: true,
    },
    gender: {
        type: String,
        enum: ['male', 'female', 'other'],
        required: true,
    },
    college: {
        type: String,
        required: true,
    },
    idNumber: {
        type: String,
        required: true,
        unique: true,
    },
    department: {
        type: String, 
        required: true,
    },
    year: {
        type: String, 
        required: true,
    },
    paymentStatus: {
        type: String,
        enum: ['pending', 'completed', 'failed'],
        default: 'pending',
        required: true,
    },
    otp: {
        type: String,
        required: false,
    },
    otpExpiration: {
        type: Date,
        required: false,
    },
    studentIDPath: {
        type: String, // File path for the student ID card
        required: true,
    },
    aadhaarCardPath: {
        type: String, // File path for the Aadhaar card
        required: true,
    },
    paymentProofPath: {
        type: String, // File path for the payment proof image
        required: false,
    },
    events: {
        type: [String], // Array of event names
        default: [], // Default to an empty array
    },
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
