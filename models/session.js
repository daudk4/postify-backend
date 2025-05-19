const mongoose = require("mongoose");

const sessionSchema = mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "user",
  },
  refreshToken: {
    type: String,
    required: true,
  },
  userAgent: String, //store user device info for session management
  createdAt: {
    type: Date,
    default: Date.now,
    expires: process.env.NODE_REFRESH_TOKEN_EXPIRES_IN,
  },
});

module.exports = mongoose.model("session", sessionSchema);
