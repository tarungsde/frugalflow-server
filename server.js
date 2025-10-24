import express from "express";
import mongoose from "mongoose";
import User from "./models/User.js";
import Transaction from "./models/Transaction.js";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import cors from "cors";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import { GoogleGenerativeAI } from "@google/generative-ai";
import jwt from "jsonwebtoken";

dotenv.config();

const generateToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email },
    process.env.JWT_SECRET || 'your-callback-secret',
    { expiresIn: "7d" }
  );
};

const verifyToken = (token) => {
    return jwt.verify(token, process.env.JWT_SECRET || 'your-callback-secret');
};

const app = express();
const port = process.env.PORT;
const saltRounds = parseInt(process.env.SALT_ROUNDS);
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

app.use(express.json());
app.use(
  cors({
    origin: process.env.APPLICATION_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  })
);
app.use(passport.initialize());

// =============================
// Database Connection
// =============================
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to DB successfully"))
  .catch((err) => console.error("Error while connecting to DB:", err));

// =============================
// Routes
// =============================
app.get("/", (req, res) => {
  res.json("Server is running.");
});

// Google Auth

app.get("/auth/google/otunar", 
  passport.authenticate("google", { 
    failureRedirect: process.env.APPLICATION_URL + "/login?error=Google authentication failed",
    session: false
  }),
  (req, res) => {
    // Successful authentication
    console.log("Callback - User authenticated:", req.user ? req.user.email : "No user");
    
    const token = generateToken(req.user);
    const redirectUrl = `${process.env.APPLICATION_URL}/auth/success?token=${token}`;
    res.redirect(redirectUrl);
  }
);

app.get("/logout", (req, res, next) => {
  req.logOut((err) => {
    if (err) return next(err);
    res.clearCookie("connect.sid");
    res.status(200).json({ success: true, message: "Logged out successfully" });
  });
});

// =============================
// Middleware
// =============================

const ensureAuth = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = verifyToken(token);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// =============================
// Transaction Routes
// =============================
app.get("/all-transactions", ensureAuth, async (req, res) => {
  try {
    const allTransaction = await Transaction.find({ userId: req.userId });
    res.json(allTransaction);
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).json({ message: "Failed to fetch transactions" });
  }
});

app.get("/filter", ensureAuth, async (req, res) => {
  const { type, category, startDate, endDate } = req.query;
  try {
    let filter = { userId: req.userId };
    if (type) {
      filter.type = type;
      if (category) filter.category = category;
    }
    if (startDate || endDate) {
      filter.date = {};
      if (startDate) filter.date.$gte = new Date(startDate);
      if (endDate) {
        let end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        filter.date.$lte = end;
      }
    }
    const filteredData = await Transaction.find(filter).sort({ date: -1 });
    res.json(filteredData);
  } catch (error) {
    console.log("Error before filtering : ", error);
  }
});

app.get("/generate-report", ensureAuth, async (req, res) => {
  try {
    const month = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
    const transactions = await Transaction.find({
      userId: req.userId,
      date: { $gte: month },
    });

    const totalIncome = transactions
      .filter((t) => t.type === "income")
      .reduce((a, b) => a + b.amount, 0);

    const totalExpense = transactions
      .filter((t) => t.type === "expense")
      .reduce((a, b) => a + b.amount, 0);

    const balance = totalIncome - totalExpense;

    const summary = `Income : ₹${totalIncome} Expense : ₹${totalExpense} Balance : ₹${balance} Categories Breakdown: ${JSON.stringify(
      transactions.map((t) => `${t.category}: ₹${t.amount}`)
    )}`;

    const prompt = `Here is a user's financial summary for this month:\n${summary}\n Please generate a simple financial report with:
1. Summary of income and expenses.
2. Advice on savings and budgeting.
3. Summary and advice should contain around 70 words each in a paragraph.
4. Tone should be friendly and encouraging.
5. Provide the report in plain text without any markdown formatting.
6. Only contain 2 paragraphs in total.
7. In between the 2 paragraphs, add a || symbol.`;

    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
    const result = await model.generateContent(prompt);
    const reportText = result.response.text();

    res.json({ report: reportText });
  } catch (error) {
    console.error("Erros while generating report", error);
    res.status(500).json({ report: "Failed to generate report due to server error." });
  }
});

// =============================
// Auth Routes
// =============================


app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(404).json({ message: "Account already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    req.login(newUser, (err) => {
      if (err) {
        console.error("Login error after registration:", err);
        return res.status(500).json({ message: "Login failed after registration" });
      }
      return res.status(201).json({ message: "User registered and logged in successfully" });
    });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ message: "Registration failed" });
  }
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: info?.message || "Login failed" });
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.status(200).json({ success: true, message: "Login successful", user });
    });
  })(req, res, next);
});

// =============================
// CRUD Operations for Transactions
// =============================
app.post("/add-transaction", ensureAuth, async (req, res) => {
  try {
    const { type, category, amount, date, description } = req.body;
    const newTransaction = new Transaction({
      type,
      category,
      amount,
      date,
      description,
      userId: req.userId,
    });
    await newTransaction.save();
    res.status(201).json({ message: "Transaction received" });
  } catch (err) {
    console.error("Error saving transaction:", err);
    res.status(500).json({ message: "Failed to save transaction" });
  }
});

app.put("/update-transaction/:id", ensureAuth, async (req, res) => {
  try {
    const transactionId = req.params.id;
    const { type, category, amount, description, date } = req.body;

    const updated = await Transaction.findOneAndUpdate(
      { _id: transactionId, userId: req.userId },
      { type, category, amount, description, date },
      { new: true }
    );

    if (!updated) {
      return res.status(404).json({ message: "Transaction not found" });
    }

    res.status(200).json({ message: "Transaction updated successfully", updated });
  } catch (error) {
    console.error("Error updating transaction:", error);
    res.status(500).json({ message: "Failed to update transaction" });
  }
});

app.delete("/delete-transaction/:id", ensureAuth, async (req, res) => {
  try {
    const transactionId = req.params.id;
    await Transaction.deleteOne({ _id: transactionId, userId: req.userId });
    res.status(200).json({ message: "Transaction deleted successfully" });
  } catch (error) {
    console.error("Error deleting transaction:", error);
    res.status(500).json({ message: "Failed to delete transaction" });
  }
});

// =============================
// Passport Configuration
// =============================
passport.use(
  "local",
  new Strategy({ usernameField: "email" }, async function verify(email, password, cb) {
    try {
      const existingUser = await User.findOne({ email });
      if (!existingUser) {
        console.log("Account does not exist.");
        return cb(null, false, { message: "Account does not exist" });
      }

      const isMatch = await bcrypt.compare(password, existingUser.password);
      if (!isMatch) {
        console.log("Invalid Credentials");
        return cb(null, false, { message: "Invalid Credentials" });
      }

      return cb(null, existingUser);
    } catch (err) {
      console.error("Error during authentication:", err);
      return cb(err);
    }
  })
);

// Google Auth Strategy
passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
  try {
    console.log("Google profile received:", profile.email); // Debug log
    const existingUser = await User.findOne({ email: profile.email });
    if (existingUser) {
      cb(null, existingUser);
    } else {
      const newUser = new User({
        email: profile.email,
        password: "google",
      });
      await newUser.save();
      console.log("New user created:", newUser.email);
      cb(null, newUser);
    }
  } catch (err) {
    console.log("Google strategy error:", err);
    return cb(err);
  }
}));

// =============================
// Server Start
// =============================
app.listen(port, () => {
  console.log(`App is running on http://localhost:${port}.`);
});
