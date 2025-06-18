const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema(
  {
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Conversation",
      required: true,
    },
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    receiver: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    // Store encrypted message for both sender and receiver
    encryptedForSender: {
      type: String,
      required: true,
    },
    encryptedForReceiver: {
      type: String,
      required: true,
    },
    isRead: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// Add indexes for better performance
messageSchema.index({ conversationId: 1, createdAt: 1 });
messageSchema.index({ sender: 1 });
messageSchema.index({ receiver: 1 });

module.exports = mongoose.model("Message", messageSchema);