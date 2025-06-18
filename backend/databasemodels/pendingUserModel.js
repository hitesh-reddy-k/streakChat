const mongoose = require("mongoose");

const pendingUserSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    otp: String,
    otpExpire: Date,
}, {
    timestamps: true,
});


pendingUserSchema.index({ otpExpire: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("PendingUser", pendingUserSchema);
