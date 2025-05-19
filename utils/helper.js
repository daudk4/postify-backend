const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: process.env.NODE_EMAIL_SERVICE,
  auth: {
    user: process.env.NODE_EMAIL_USER,
    pass: process.env.NODE_EMAIL_PASSWORD,
  },
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(email, otp) {
  try {
    const mailOptions = {
      from: process.env.NODE_EMAIL_USER,
      to: email,
      subject: "Your OTP for Account Verification",
      html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Account Verification</h2>
            <p>Thank you for signing up! Please use the following OTP to verify your email address:</p>
            <div style="background-color: #f4f4f4; padding: 15px; border-radius: 5px; text-align: center; font-size: 24px; letter-spacing: 5px;">
            <strong>${otp}</strong>
            </div>
            <p>This OTP will expire in 5 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
            </div>
            `,
    };
    return transporter.sendMail(mailOptions);
  } catch (error) {
    console.log("error in sendOTPEmail", error);
  }
}

function generateTokens(payload) {
  const accessToken = jwt.sign(payload, process.env.NODE_JWT_SECRET_KEY, {
    expiresIn: process.env.NODE_ACCESS_TOKEN_EXPIRES_IN,
  });

  const refreshToken = crypto.randomBytes(64).toString("hex");

  return { accessToken, refreshToken };
}

module.exports = { generateOTP, sendOTPEmail, generateTokens };
