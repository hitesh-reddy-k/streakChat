const crypto = require("crypto");
const User = require("../databasemodels/usermodel");
const nodemailer = require("nodemailer");
const PendingUser = require("../databasemodels/pendingUserModel");
const bcrypt = require("bcrypt");

// Email setup
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD
    }
});

function generateRSAKeyPair() {
    try {
        console.log("🔑 Generating RSA key pair...");
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: { type: "pkcs1", format: "pem" },
            privateKeyEncoding: { type: "pkcs1", format: "pem" }
        });
        console.log("✅ RSA key pair generated successfully");
        console.log("📊 Public key length:", publicKey.length);
        console.log("📊 Private key length:", privateKey.length);
        return { publicKey, privateKey };
    } catch (error) {
        console.error("❌ Error generating RSA key pair:", error);
        throw error;
    }
}

// Helper: Sign a message using RSA
function signKey(data, privateKey) {
    try {
        console.log("🔏 Signing key with RSA...");
        const signature = crypto.createSign("SHA256").update(data).sign(privateKey, "base64");
        console.log("✅ Key signed successfully");
        return signature;
    } catch (error) {
        console.error("❌ Error signing key:", error);
        throw error;
    }
}

// Generate multiple one-time prekeys
function generatePreKeys(count = 10) {
    try {
        console.log(`🔑 Generating ${count} one-time prekeys...`);
        const keys = [];
        for (let i = 0; i < count; i++) {
            const { publicKey } = generateRSAKeyPair();
            keys.push({ keyId: i + 1, publicKey });
        }
        console.log(`✅ Generated ${keys.length} one-time prekeys`);
        return keys;
    } catch (error) {
        console.error("❌ Error generating prekeys:", error);
        throw error;
    }
}

// Main registration controller
const registerUser = async (req, res) => {
    try {
        console.log("🚀 Starting user registration process...");
        
        // Sanitize and normalize input
        const username = req.body.username?.trim().toLowerCase();
        const password = req.body.password;
        const confirmPassword = req.body.confirmPassword;
        const email = req.body.email?.trim().toLowerCase();
        const phoneNumber = req.body.phoneNumber?.trim();

        console.log("📝 Registration request received:", { 
            username, 
            email, 
            phoneNumber,
            hasPassword: !!password,
            hasConfirmPassword: !!confirmPassword
        });

        if (!username || !password || !confirmPassword || !email || !phoneNumber) {
            console.log("❌ Missing required fields");
            return res.status(400).json({ message: "All fields are required" });
        }

        if (password !== confirmPassword) {
            console.log("❌ Passwords do not match");
            return res.status(400).json({ message: "Passwords do not match" });
        }

        // Check if user already exists
        console.log("🔍 Checking for existing user...");
        const existingUser = await User.findOne({
            $or: [
                { email },
                { username },
                { phoneNumber }
            ]
        });

        if (existingUser) {
            console.log("❌ User already exists:", {
                foundBy: existingUser.email === email ? 'email' : 
                         existingUser.username === username ? 'username' : 'phone'
            });
            
            if (existingUser.email === email) {
                return res.status(400).json({ message: "Email already registered" });
            }
            if (existingUser.username === username) {
                return res.status(400).json({ message: "Username already taken" });
            }
            if (existingUser.phoneNumber === phoneNumber) {
                return res.status(400).json({ message: "Phone number already registered" });
            }
            return res.status(400).json({ message: "User already exists" });
        }

        // Also check pending users to avoid conflicts
        console.log("🔍 Checking for existing pending user...");
        const existingPendingUser = await PendingUser.findOne({
            $or: [
                { email },
                { username },
                { phoneNumber }
            ]
        });

        if (existingPendingUser) {
            console.log("⚠️ Found existing pending user");
            if (existingPendingUser.email === email) {
                console.log("🗑️ Removing existing pending user with same email");
                await PendingUser.deleteOne({ email });
            } else {
                if (existingPendingUser.username === username) {
                    return res.status(400).json({ message: "Username already taken (pending verification)" });
                }
                if (existingPendingUser.phoneNumber === phoneNumber) {
                    return res.status(400).json({ message: "Phone number already registered (pending verification)" });
                }
            }
        }

        console.log("🎲 Generating OTP...");
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        console.log("📧 OTP Details:", { 
            otp: process.env.NODE_ENV === 'development' ? otp : '[HIDDEN]',
            expiresAt: otpExpire 
        });

        // Hash password
        console.log("🔒 Hashing password...");
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log("✅ Password hashed successfully");

        // Save pending user
        console.log("💾 Creating pending user...");
        const pendingUser = new PendingUser({
            username,
            password: hashedPassword,
            email,
            phoneNumber,
            otp,
            otpExpire
        });

        const savedPendingUser = await pendingUser.save();
        console.log("✅ Pending user saved with ID:", savedPendingUser._id);

        // Send OTP email
        console.log("📧 Sending OTP email...");
        await transporter.sendMail({
            from: `"StreakChat" <${process.env.EMAIL_USERNAME}>`,
            to: email,
            subject: "Verify your StreakChat OTP",
            html: `<p>Your OTP is <b>${otp}</b>. It expires in 10 minutes.</p>`,
        });

        console.log("✅ OTP email sent successfully");

        res.status(200).json({ 
            message: "OTP sent to your email. Please verify to complete registration.",
            ...(process.env.NODE_ENV === 'development' && { debug: { email, otp } })
        });

    } catch (error) {
        console.error("❌ Register Error:", error);
        res.status(500).json({ message: "Something went wrong during registration." });
    }
};

const verifyOtp = async (req, res) => {
    try {
        console.log("🔍 Starting OTP verification...");
        const { email, otp } = req.body;

        console.log("📝 OTP verification request:", { 
            email, 
            otp: process.env.NODE_ENV === 'development' ? otp : '[HIDDEN]'
        });

        if (!email || !otp) {
            console.log("❌ Missing email or OTP");
            return res.status(400).json({ message: "Email and OTP are required" });
        }

        console.log("🔍 Finding pending user...");
        const pendingUser = await PendingUser.findOne({ email: email.trim().toLowerCase() });

        if (!pendingUser) {
            console.log("❌ No pending registration found for email:", email);
            return res.status(404).json({ message: "No pending registration found" });
        }

        console.log("⏰ Verifying OTP and expiration...");
        console.log("📊 OTP Details:", {
            provided: process.env.NODE_ENV === 'development' ? otp : '[HIDDEN]',
            stored: process.env.NODE_ENV === 'development' ? pendingUser.otp : '[HIDDEN]',
            isExpired: pendingUser.otpExpire < Date.now(),
            expiresAt: pendingUser.otpExpire,
            currentTime: new Date()
        });

        if (pendingUser.otp !== otp || pendingUser.otpExpire < Date.now()) {
            console.log("❌ Invalid or expired OTP");
            return res.status(400).json({ message: "Invalid or expired OTP" });
        }

        // Double-check that no user was created in the meantime
        console.log("🔍 Double-checking for existing user...");
        const existingUser = await User.findOne({
            $or: [
                { email: pendingUser.email },
                { username: pendingUser.username },
                { phoneNumber: pendingUser.phoneNumber }
            ]
        });

        if (existingUser) {
            console.log("❌ User already exists, cleaning up pending user");
            await PendingUser.deleteOne({ email: email.trim().toLowerCase() });
            return res.status(400).json({ message: "User already exists. Please try logging in." });
        }

        // Generate keys for encryption
        console.log("🔑 Generating encryption keys...");
        const identityKeyPair = generateRSAKeyPair();
        const signedPreKeyPair = generateRSAKeyPair();
        
        console.log("🔏 Creating signed prekey...");
        const signedPreKey = {
            keyId: 1,
            publicKey: signedPreKeyPair.publicKey,
            signature: signKey(signedPreKeyPair.publicKey, identityKeyPair.privateKey),
        };
        
        console.log("🔑 Generating one-time prekeys...");
        const oneTimePreKeys = generatePreKeys(10);

        // Create real User
        console.log("👤 Creating new user...");
        const newUser = new User({
            username: pendingUser.username,
            password: pendingUser.password,
            email: pendingUser.email,
            phoneNumber: pendingUser.phoneNumber,
            identityKey: identityKeyPair.publicKey,
            privateKey: identityKeyPair.privateKey, // Store private key
            publicKey: identityKeyPair.publicKey,   // Store public key for easy access
            signedPreKey,
            oneTimePreKeys
        });

        console.log("💾 Saving new user...");
        const savedUser = await newUser.save();
        console.log("✅ New user created with ID:", savedUser._id);

        console.log("🗑️ Cleaning up pending user...");
        await PendingUser.deleteOne({ email: email.trim().toLowerCase() });
        console.log("✅ Pending user cleaned up");

        res.status(201).json({ message: "Account verified and created successfully" });

    } catch (error) {
        console.error("❌ OTP Verification Error:", error);
        res.status(500).json({ message: "Could not verify OTP" });
    }
};

const loginUser = async (req, res) => {
    try {
        console.log("🔐 Starting user login...");
        
        const { identifier, password } = req.body;

        console.log("📝 Login request:", { 
            identifier, 
            hasPassword: !!password 
        });

        if (!identifier || !password) {
            console.log("❌ Missing identifier or password");
            return res.status(400).json({ message: "Username, Email, or Phone number and Password are required" });
        }

        // Normalize identifier
        const normalizedIdentifier = identifier.trim().toLowerCase();
        console.log("🔍 Searching for user with identifier:", normalizedIdentifier);

        // Find user by email, username, or phoneNumber
        const user = await User.findOne({
            $or: [
                { email: normalizedIdentifier },
                { username: normalizedIdentifier },
                { phoneNumber: identifier.trim() } // Don't lowercase phone numbers
            ]
        }).select("+password");

        if (!user) {
            console.log("❌ User not found");
            return res.status(404).json({ message: "User not found or not verified" });
        }

        console.log("✅ User found:", { 
            id: user._id, 
            username: user.username,
            email: user.email 
        });

        console.log("🔒 Verifying password...");
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            console.log("❌ Invalid password");
            return res.status(401).json({ message: "Incorrect password" });
        }

        console.log("✅ Password verified");

        // Set user online
        console.log("📱 Setting user online status...");
        user.isOnline = true;
        user.lastSeen = Date.now();
        await user.save();

        // Generate JWT token
        console.log("🎫 Generating JWT token...");
        const token = user.getJWTToken();

        console.log("✅ Login successful for user:", user._id);

        res.status(200).json({
            message: "Login successful",
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                phoneNumber: user.phoneNumber,
                profilePicture: user.profilePicture,
                status: user.status,
                lastSeen: user.lastSeen,
                isOnline: user.isOnline
            }
        });

    } catch (error) {
        console.error("❌ Login Error:", error);
        res.status(500).json({ message: "Login failed. Please try again later." });
    }
};

module.exports = { registerUser, verifyOtp, loginUser };