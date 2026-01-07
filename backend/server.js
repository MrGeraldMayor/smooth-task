const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '5mb' })); 

// 1. Database Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch((err) => console.error('❌ MongoDB connection error:', err));

// 2. User Schema
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profilePhoto: { type: String, default: "" }, 
    verifiedAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// 3. Task Schema
const taskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    completed: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const Task = mongoose.model('Task', taskSchema);

// 4. Email Transport
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    tls: { rejectUnauthorized: false }
});

// --- AUTH ROUTES ---

app.post('/api/send-otp', async function(req, res) {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });
    const otp = Math.floor(100000 + Math.random() * 900000);
    const mailOptions = {
        from: `"Verification Team" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: `Your Verification Code: ${otp}`,
        html: `<h2>Code: ${otp}</h2>`
    };
    transporter.sendMail(mailOptions, (err) => {
        if (err) return res.status(500).json({ message: "Mail failed" });
        res.status(200).json({ otp: otp });
    });
});

app.post('/api/register-final', async function(req, res) {
    try {
        const { firstName, lastName, email, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ firstName, lastName, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: "Registration successful!" });
    } catch (error) { res.status(500).json({ message: "Database error" }); }
});

app.post('/api/login', async function(req, res) {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: "Invalid email or password" });
        }
        res.status(200).json({
            message: "Login successful",
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                profilePhoto: user.profilePhoto 
            }
        });
    } catch (error) { res.status(500).json({ message: "Server error" }); }
});

// --- USER PROFILE ROUTES ---

// UPDATE OR REMOVE PHOTO
app.patch('/api/user/update-photo', async (req, res) => {
    try {
        const { userId, photo } = req.body; 
        if (!userId) return res.status(400).json({ message: "User ID is required" });

        // If photo is passed as null or empty string, it removes the photo
        const updatedUser = await User.findByIdAndUpdate(
            userId, 
            { profilePhoto: photo || "" }, 
            { new: true }
        );
        
        res.json({ 
            message: "Profile updated", 
            profilePhoto: updatedUser.profilePhoto 
        });
    } catch (err) {
        res.status(500).json({ message: "Error updating photo" });
    }
});

// DELETE ENTIRE ACCOUNT AND ALL TASKS (The Wipe)
app.delete('/api/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        // 1. Delete all tasks belonging to this user
        const deletedTasks = await Task.deleteMany({ userId: userId });
        
        // 2. Delete the user profile
        const deletedUser = await User.findByIdAndDelete(userId);

        if (!deletedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        console.log(`Successfully deleted user ${userId} and ${deletedTasks.deletedCount} tasks.`);
        
        res.json({ message: "Account and all associated data deleted forever." });
    } catch (err) {
        console.error("Delete Error:", err);
        res.status(500).json({ message: "Server error during deletion" });
    }
});

// --- TASK ROUTES ---

app.get('/api/tasks/:userId', async function(req, res) {
    try {
        const tasks = await Task.find({ userId: req.params.userId }).sort({ createdAt: -1 });
        res.json(tasks);
    } catch (error) { res.status(500).json({ message: "Error fetching tasks" }); }
});

app.post('/api/tasks', async function(req, res) {
    try {
        const { userId, text } = req.body;
        const newTask = new Task({ userId, text });
        await newTask.save();
        res.status(201).json(newTask);
    } catch (error) { res.status(500).json({ message: "Error saving task" }); }
});

app.patch('/api/tasks/:taskId', async function(req, res) {
    try {
        const task = await Task.findById(req.params.taskId);
        task.completed = !task.completed;
        await task.save();
        res.json(task);
    } catch (error) { res.status(500).json({ message: "Error updating task" }); }
});

app.delete('/api/tasks/:taskId', async function(req, res) {
    try {
        await Task.findByIdAndDelete(req.params.taskId);
        res.json({ message: "Task deleted" });
    } catch (error) { res.status(500).json({ message: "Error deleting task" }); }
});



// --- FORGOT PASSWORD ROUTES ---

// 1. Send OTP for Password Reset
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: "Email is required" });

        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "No account found with this email" });
        }

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000);

        const mailOptions = {
            from: `"Security Team" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Password Reset Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px;">
                    <h2 style="color: #1976d2;">Reset Your Password</h2>
                    <p>We received a request to reset your password. Use the code below to proceed:</p>
                    <div style="background: #f4f4f4; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px;">
                        ${otp}
                    </div>
                    <p>This code is valid for a limited time. If you didn't request this, please ignore this email.</p>
                </div>
            `
        };

        transporter.sendMail(mailOptions, (err) => {
            if (err) return res.status(500).json({ message: "Failed to send reset email" });
            
            // Sending OTP back to frontend for verification 
            // (Note: In a production app, save this to DB with an expiry instead)
            res.status(200).json({ 
                message: "Reset code sent to your email", 
                otp: otp 
            });
        });
    } catch (error) {
        res.status(500).json({ message: "Server error during forgot password" });
    }
});

// 2. Update Password (Final Step)
app.post('/api/reset-password', async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update user's password
        const updatedUser = await User.findOneAndUpdate(
            { email: email },
            { password: hashedPassword },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ message: "Password updated successfully! You can now login." });
    } catch (error) {
        res.status(500).json({ message: "Error updating password" });
    }
});







const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server on http://localhost:${PORT}`));