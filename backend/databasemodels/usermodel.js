const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const PreKeySchema = new mongoose.Schema({
    keyId: { type: Number, required: true },
    publicKey: { type: String, required: true }, // Usually base64
});

const SignedPreKeySchema = new mongoose.Schema({
    keyId: { type: Number, required: true },
    publicKey: { type: String, required: true },
    signature: { type: String, required: true },
});

// Main User schema
const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        validate: [validator.isEmail, "Please enter a valid email"],
    },
    phoneNumber: {
        type: String,
        required: true,
        unique: true,
        validate: {
            validator: (v) => /^\d{10}$/.test(v),
            message: "Phone number must be 10 digits",
        },
    },
    password: {
        type: String,
        required: true,
        select: false, // Don't return password by default
    },
    profilePicture: {
        type: String,
        default: "", 
    },
    status: {
        type: String,
        default: "Hey there! I am using StreakChat",
    },
    lastSeen: {
        type: Date,
        default: Date.now,
    },
    isOnline: {
        type: Boolean,
        default: false,
    },
    contacts: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
        },
    ],

    // E2EE keys - FIXED: Added private key storage
    identityKey: {
        type: String,
        required: true,
    },
    // Store the private key securely (in production, consider additional encryption)
    privateKey: {
        type: String,
        required: true,
        select: false, // Don't return by default for security
    },
    // Public key for others to encrypt messages to this user
    publicKey: {
        type: String,
        required: true,
    },
    signedPreKey: {
        type: SignedPreKeySchema,
        required: true,
    },
    oneTimePreKeys: {
        type: [PreKeySchema],
        default: [],
    },

    // OTP and reset password flow
    otp: String,
    otpExpire: Date,
    resetPasswordToken: String,
    resetPasswordExpire: Date,
}, { timestamps: true });

// Encrypt password before saving
UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();

    const isAlreadyHashed = /^\$2[ayb]\$.{56}$/.test(this.password);
    if (!isAlreadyHashed) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

// Compare plain text password with hashed one
UserSchema.methods.comparePassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

// Generate JWT
UserSchema.methods.getJWTToken = function () {
    return jwt.sign(
        { id: this._id },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRE }
    );
};

// Generate Reset Password Token
UserSchema.methods.getResetPasswordToken = function () {
    const resetToken = crypto.randomBytes(20).toString("hex");
    this.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
    this.resetPasswordExpire = Date.now() + 15 * 60 * 1000; // 15 mins
    return resetToken;
};

module.exports = mongoose.model("User", UserSchema);