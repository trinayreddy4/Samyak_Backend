// emailService.js
const nodemailer = require('nodemailer');
require('dotenv').config();

// Function to send confirmation email
const sendConfirmationEmail = async (email, firstname) => {
    try {
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
            subject: 'Samyak2024 Registration Successful',
            text: `Hello ${firstname},\n\nThank you for registering for the Samyak Event! 
            We're excited to have you on board and can't wait to see your participation.
            Please ensure to check your email for further updates and event schedules.
            \n\nIf you have any questions, feel free to reach out to our support team at 
            [support@samyak2024.com] or visit our website for more details.
            \n\nBest regards,\nThe Samyak 2024 Team\n\n
            Follow us on social media for the latest news and updates:\nFacebook: https://www.facebook.com/kl.samyak/\n
            Instagram: https://www.instagram.com/kl.samyak/?hl=en\n`,
        };

        // Sending email
        await transporter.sendMail(mailOptions);
        console.log(`Confirmation email sent to ${email}`);
    } catch (error) {
        console.error(`Failed to send email to ${email}:`, error);
        // Handle the error or notify the user/admin about the failure
    }
};

module.exports = { sendConfirmationEmail };

