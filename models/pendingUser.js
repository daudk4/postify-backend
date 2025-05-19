const mongoose = require("mongoose");

const pendingUserSchema = mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  name: {
    type: String,
    required: true,
  },
  age: {
    type: Number,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  otp: {
    type: String,
    reqired: true,
  },
  otpExpiry: {
    type: Date,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  ttl: {
    type: Date,
    default: () => new Date(Date.now() + 5 * 60 * 1000), // 5 minutes from now
    index: { expires: 0 },
  },
});

module.exports = mongoose.model("pendingUser", pendingUserSchema);
