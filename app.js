require("dotenv").config();
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const express = require("express");
const jwt = require("jsonwebtoken");

const cookieParser = require("cookie-parser");
const {
  userModel,
  postModel,
  pendingUserModel,
  sessionModel,
} = require("./models");
const { generateOTP, sendOTPEmail, generateTokens } = require("./utils/helper");

const server = express();
// server.set("view engine", "ejs");

server.use(cookieParser());
server.use(express.json());
server.use(express.urlencoded());
server.use(express.static(path.join(__dirname, "public")));

const allowedOrigins = ["http://localhost:5173", "http://localhost:5174"];
server.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true, // enable cookies, auth headers
  })
);

// server.get("/", (req, res) => {
//   res.render("signup");
// });

// server.get("/signin", (req, res) => {
//   res.render("signin");
// });

server.get("/getUser", isLoggedIn, async (req, res) => {
  try {
    const { email, userId } = req.user;
    const user = await userModel.findOne({ _id: userId }).populate("posts");

    if (!user) {
      return res.status(404).json({
        message: "User not found",
        expired: true,
      });
    }

    return res.status(200).json({ data: user });
  } catch (error) {
    console.error("Error in getUser:", error);
    return res.status(500).json({
      message: "Failed to retrieve user. Please try again later.",
      expired: true,
    });
  }
});

server.get("/like/:postid", isLoggedIn, async (req, res) => {
  try {
    // Find the post by ID
    const post = await postModel.findOne({ _id: req.params.postid });
    if (!post) {
      // If AJAX request, return JSON response
      if (req.xhr) {
        return res.json({ success: false, message: "Post not found" });
      }
      return res.redirect("/profile");
    }
    const userLikedIndex = post.likes.indexOf(req.user.userId);
    let liked = false;

    if (userLikedIndex === -1) {
      post.likes.push(req.user.userId);
      liked = true;
    } else {
      post.likes.splice(userLikedIndex, 1);
      liked = false;
    }
    await post.save();

    if (req.xhr) {
      return res.json({
        success: true,
        liked: liked,
        likeCount: post.likes.length,
      });
    }
    res.redirect("/profile");
  } catch (error) {
    console.error("Error in like route:", error);
    if (req.xhr) {
      return res.status(500).json({ success: false, message: "Server error" });
    }
    res.redirect("/profile");
  }
});

server.post("/edit/:postId", isLoggedIn, async (req, res) => {
  const { postId } = req.params;
  const post = await postModel
    .findOneAndUpdate({ _id: postId }, { content: req.body.content })
    .populate("user");
  res.redirect("/profile");
});

server.post("/post", isLoggedIn, async (req, res) => {
  try {
    const { email, userId } = req.user;
    const { content } = req.body;
    const user = await userModel.findOne({ _id: userId });
    const post = await postModel.create({
      user: user._id,
      content,
    });

    await user.updateOne({ $push: { posts: post } });
    return res.status(200).json({ message: "Post created successfully!" });
  } catch (error) {}
});

server.post("/signup", async (req, res) => {
  try {
    const { username, name, email, age, password } = req.body;
    const user = await userModel.findOne({ email });

    if (user) {
      const err = new Error("User already registered!");
      err.status = 409;
      throw err;
    }

    const pendingUser = await pendingUserModel.findOne({ email });
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
    const salt = await bcrypt.genSalt(12);
    const hashedPass = await bcrypt.hash(password, salt);

    if (pendingUser) {
      pendingUser.otp = otp;
      pendingUser.otpExpiry = otpExpiry;
      pendingUser.username = username;
      pendingUser.email = email;
      pendingUser.age = age;
      pendingUser.name = name;
      pendingUser.password = hashedPass;
      pendingUser.ttl = new Date(Date.now() + 5 * 60 * 1000);
      await pendingUser.save();
    } else {
      const newPendingUser = await pendingUserModel.create({
        username,
        name,
        email,
        age,
        password: hashedPass,
        otp,
        otpExpiry,
      });
    }

    await sendOTPEmail(email, otp);
    return res.status(200).json({
      message:
        "OTP sent to your email. Please verify to complete registration.",
    });
  } catch (error) {
    return res.status(error.status).json({ message: error.message });
  }
});

server.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const pendingUser = await pendingUserModel.findOne({ email });

    if (pendingUser) {
      const isExpired = new Date() >= pendingUser.otpExpiry;
      const isValidOTP = pendingUser.otp === otp;

      if (isExpired) {
        return res
          .status(410)
          .json({ message: "OTP has expired. Please try again." });
      } else if (!isValidOTP) {
        return res
          .status(401)
          .json({ message: "Invalid OTP. Please try again." });
      }

      const createdUser = await userModel.create({
        username: pendingUser.username,
        name: pendingUser.name,
        email: pendingUser.email,
        age: pendingUser.age,
        password: pendingUser.password, // Password is already hashed
      });

      await pendingUserModel.deleteOne({ email });
      return res.status(201).json({
        message: "Account created successfully! Please sign in to continue.",
      });
    } else {
      return res.status(400).json({
        message: "No pending verification found. Please sign up again.",
      });
    }
  } catch (error) {
    return res.status(500).json({ message: "Error creating account" });
  }
});

server.post("/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    const pendingUser = await pendingUserModel.findOne({ email });

    if (!pendingUser) {
      return res.status(400).json({
        message: "No pending verification found. Please sign up again.",
      });
    } else {
      const newExpiryTime = Date.now() + 5 * 60 * 1000;
      const otp = generateOTP();
      const otpExpiry = new Date(newExpiryTime);
      pendingUser.otp = otp;
      pendingUser.otpExpiry = otpExpiry;
      pendingUser.ttl = new Date(newExpiryTime);
      await pendingUser.save();

      await sendOTPEmail(email, otp);
      return res.status(200).json({
        message: "OTP sent successfully!",
      });
    }
  } catch (error) {
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

server.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const user = await userModel.findOne({ email });
  const isValidPassword = await bcrypt.compare(password, user.password);

  if (!user || !isValidPassword)
    return res.status(401).json({ message: "Invalid Credentials" });

  const payload = { email, userId: user._id };
  const { accessToken, refreshToken } = generateTokens(payload);

  await sessionModel.create({
    userId: user._id,
    refreshToken,
    userAgent: req.headers["user-agent"],
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.status(200).json({ data: accessToken });
});

server.post("/refresh-token", async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token)
    return res.status(401).json({ message: "No refresh token provided" });

  const session = await sessionModel.findOne({ refreshToken: token });
  if (!session)
    return res.status(403).json({ message: "Invalid refresh token" });

  const user = await userModel.findById(session.userId);
  if (!user) return res.status(404).json({ message: "User not found" });

  const payload = { email: user.email, userId: user._id };
  const { accessToken, refreshToken: newRefreshToken } =
    generateTokens(payload);

  session.refreshToken = newRefreshToken;
  await session.save();

  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return res.status(200).json({ data: accessToken });
});

server.get("/logout", async (req, res) => {
  const token = req.cookies.refreshToken;
  if (token) await sessionModel.deleteOne({ refreshToken: token });
  res.clearCookie("refreshToken");
  return res.status(200).json({ message: "Logged out successfully!" });
});

//middleware function:
function isLoggedIn(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer "))
      return res.status(401).json({ message: "Unauthorized!" });

    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "Unauthorized!" });
    }

    try {
      const data = jwt.verify(token, process.env.NODE_JWT_SECRET_KEY);
      req.user = data;
      next();
    } catch (jwtError) {
      // Handle token expiration specifically
      if (jwtError.name === "TokenExpiredError") {
        return res.status(401).json({
          message: "Token expired",
          expired: true,
        });
      }

      // Handle other JWT errors
      return res.status(401).json({ message: "Invalid token" });
    }
  } catch (error) {
    console.error("Auth middleware error:", error);
    return res.status(500).json({
      message: "Server error. Please try again later.",
    });
  }
}

server.listen(3000, () => {
  console.log("Server is up and ready...");
});
