const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();
require('dotenv').config();
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const { sendConfirmationEmail } = require('../EmailServices')
// working route 
router.get('/',async(req,res)=>{
    return res.send("server is running..!");
})


// Define Multer storage for payment proof
const paymentProofStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'PaymentProofs'); // Destination folder for file uploads
    },
    filename: function (req, file, cb) {
        const { email } = req.body;
        console.log(req.body)
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `${email}-paymentProof-${uniqueSuffix}${path.extname(file.originalname)}`);
        console.log("first name",email)
    }
});

// Multer middleware to handle payment proof upload
const uploadPaymentProof = multer({
    storage: paymentProofStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
}).single('paymentProof');


// Register (Sign Up)
// Multer storage configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Destination folder for file uploads
    },
    filename: function (req, file, cb) {
        // Naming the file as 'firstname-lastname-studentID/aadhaarCard.ext'
        const { firstname, lastname } = req.body;
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `${firstname}-${lastname}-${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});

// Multer middleware to handle file uploads
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit for each file
}).fields([
    { name: 'studentID', maxCount: 1 },   // Field name for Student ID card
    { name: 'aadhaarCard', maxCount: 1 }, // Field name for Aadhaar card
]);

// User Signup Route
router.post('/signup', (req, res) => {
    // Use Multer to upload files
    upload(req, res, async function (err) {
        if (err) {
            return res.status(400).json({ message: 'Error uploading files', error: err.message });
        }

        const {
            firstname,
            lastname,
            email,
            password,
            phoneNumber,
            gender,
            college,
            idNumber,
            department,
            year
        } = req.body;

        // Check if required files were uploaded
        const studentID = req.files['studentID'] ? req.files['studentID'][0].filename : null;
        const aadhaarCard = req.files['aadhaarCard'] ? req.files['aadhaarCard'][0].filename : null;

        if (!studentID || !aadhaarCard) {
            return res.status(400).json({ message: 'Both student ID and Aadhaar card are required' });
        }

        try {
            // Check if user already exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ message: 'User already exists' });
            }

            // Hash the password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Create new user
            const newUser = new User({
                firstname,
                lastname,
                email,
                password: hashedPassword,
                phoneNumber,
                gender,
                college,
                idNumber,
                department,
                year,
                studentIDPath: `uploads/${studentID}`,   // Save file path for Student ID
                aadhaarCardPath: `uploads/${aadhaarCard}`, // Save file path for Aadhaar card
            });

            // Save user to DB
            await newUser.save();
            // Send confirmation email
            res.status(201).json({ message: 'User registered successfully' });
            await sendConfirmationEmail(newUser.email, newUser.firstname);
        } catch (error) {
            console.error(error.message);
            res.status(500).send('Server Error');
        }
    });
});



// Login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Compare the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT
        const payload = { userId: user._id };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ token });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

// Middleware to verify token
const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization');
    
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    try {
        // Split to remove 'Bearer ' and extract the token
        const bearerToken = token.split(' ')[1];
        const decoded = jwt.verify(bearerToken, process.env.JWT_SECRET);
        req.user = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

router.get('/user', authMiddleware, async (req, res) => {
    try {
        // Find the user by the decoded user ID
        const user = await User.findById(req.user);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Return user data, excluding the password
        const { password, ...userData } = user.toObject();
        res.status(200).json(userData);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

// Example protected route
router.get('/protected', authMiddleware, (req, res) => {
    res.status(200).json({ message: 'Access granted to protected route' });
});



// Forgot Password
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
        user.otp = otp;
        user.otpExpiration = Date.now() + 10 * 60 * 1000; // 10 minutes expiration
        await user.save();

        // Send OTP via email
        await sendOtpEmail(user.email, otp);

        res.status(200).json({ message: 'OTP sent to your email' });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});

// Function to send OTP email
const sendOtpEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail', // or another email service
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);
};

router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user || user.otp !== otp || Date.now() > user.otpExpiration) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        // Reset OTP fields
        user.otp = undefined;
        user.otpExpiration = undefined;
        await user.save();

        res.status(200).json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});

// POST route to update user events
router.post('/update-events', authMiddleware, async (req, res) => {
    const { eventNames } = req.body;

    // Ensure eventNames is an array
    if (!Array.isArray(eventNames)) {
        return res.status(400).json({ message: 'Event names are required and should be an array.' });
    }

    try {
        // Use the user ID from the token
        const userId = req.user;

        // Update the user's events
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $addToSet: { events: { $each: eventNames } } }, // Use $addToSet to avoid duplicates
            { new: true } // Return the updated user
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({ message: 'Events updated successfully.', user: updatedUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred while updating events.' });
    }
});

// Payment Proof Upload Route
router.post('/upload-payment-proof', authMiddleware, (req, res) => {
    // Use Multer to upload the payment proof
    uploadPaymentProof(req, res, async function (err) {
        if (err) {
            return res.status(400).json({ message: 'Error uploading payment proof', error: err.message });
        }

        // Extract user ID from the authenticated token
        const userId = req.user;

        // Check if the file was uploaded
        const paymentProof = req.file ? req.file.filename : null;

        if (!paymentProof) {
            return res.status(400).json({ message: 'Payment proof is required' });
        }

        try {
            // Find the user and update paymentProofPath
            const updatedUser = await User.findByIdAndUpdate(
                userId,
                { paymentProofPath: `uploads/${paymentProof}` }, // Save file path for Payment Proof
                { new: true } // Return the updated user
            );

            if (!updatedUser) {
                return res.status(404).json({ message: 'User not found' });
            }

            res.status(200).json({ message: 'Payment proof uploaded successfully', user: updatedUser });
        } catch (error) {
            console.error(error.message);
            res.status(500).json({ message: 'Server Error' });
        }
    });
});

// Fetch registered events for a user
router.get('/registered-events', authMiddleware, async (req, res) => {
    try {
        const userId = req.user; // Get userId from the decoded token
        const user = await User.findById(userId).populate('events'); // Assuming you have a reference to the events
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(user.events);
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});
  
module.exports = router;
