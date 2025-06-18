const Message = require("../databasemodels/messagemodel");
const Conversation = require("../databasemodels/conversationmodel");
const User = require("../databasemodels/usermodel");
const { encryptMessage, decryptMessage } = require("../utilites/encryption");

exports.sendMessage = async (req, res) => {
    try {
        console.log("📤 Starting send message process...");
        
        const { senderId, receiverId, message } = req.body;

        console.log("📝 Message request details:", {
            senderId,
            receiverId,
            messageLength: message?.length,
            hasMessage: !!message
        });

        // Validate input
        if (!senderId || !receiverId || !message) {
            console.log("❌ Missing required fields");
            return res.status(400).json({ message: "SenderId, receiverId, and message are required" });
        }

        if (message.trim().length === 0) {
            console.log("❌ Empty message");
            return res.status(400).json({ message: "Message cannot be empty" });
        }

        console.log("🔍 Finding sender and receiver...");
        
        // Find both sender and receiver with their public keys
        const [sender, receiver] = await Promise.all([
            User.findById(senderId).select('+publicKey'),
            User.findById(receiverId).select('+publicKey')
        ]);

        console.log("📊 User lookup results:", {
            senderFound: !!sender,
            receiverFound: !!receiver,
            senderHasPublicKey: !!sender?.publicKey,
            receiverHasPublicKey: !!receiver?.publicKey
        });

        if (!receiver) {
            console.log("❌ Receiver not found");
            return res.status(404).json({ message: "Receiver not found" });
        }
        
        if (!sender) {
            console.log("❌ Sender not found");
            return res.status(404).json({ message: "Sender not found" });
        }

        if (!sender.publicKey || !receiver.publicKey) {
            console.log("❌ Missing public keys:", {
                senderPublicKey: !!sender.publicKey,
                receiverPublicKey: !!receiver.publicKey
            });
            return res.status(400).json({ message: "User encryption keys not found" });
        }

        console.log("🔍 Finding or creating conversation...");
        
        // Find or create conversation
        let conversation = await Conversation.findOne({
            participants: { $all: [senderId, receiverId] },
        });

        if (!conversation) {
            console.log("🆕 Creating new conversation...");
            conversation = await Conversation.create({
                participants: [senderId, receiverId],
            });
            console.log("✅ New conversation created:", conversation._id);
        } else {
            console.log("✅ Existing conversation found:", conversation._id);
        }

        console.log("🔐 Encrypting message...");
        
        // Encrypt message for both sender and receiver
        let encryptedForSender, encryptedForReceiver;
        
        try {
            console.log("🔐 Encrypting for sender...");
            encryptedForSender = encryptMessage(message, sender.publicKey);
            console.log("✅ Message encrypted for sender, length:", encryptedForSender.length);
            
            console.log("🔐 Encrypting for receiver...");
            encryptedForReceiver = encryptMessage(message, receiver.publicKey);
            console.log("✅ Message encrypted for receiver, length:", encryptedForReceiver.length);
            
        } catch (encryptionError) {
            console.error("❌ Encryption error:", encryptionError);
            return res.status(500).json({ message: "Failed to encrypt message" });
        }

        console.log("💾 Saving message to database...");
        
        // Save message with both encrypted versions
        const newMessage = await Message.create({
            conversationId: conversation._id,
            sender: senderId,
            receiver: receiverId,
            encryptedForSender,
            encryptedForReceiver,
        });

        console.log("✅ Message saved with ID:", newMessage._id);

        console.log("🔄 Updating conversation...");
        
        // Update last message in conversation
        conversation.lastMessage = newMessage._id;
        await conversation.save();

        console.log("✅ Conversation updated");

        console.log("📤 Message sent successfully");

        res.status(201).json({ 
            message: "Message sent successfully", 
            data: {
                messageId: newMessage._id,
                conversationId: conversation._id,
                timestamp: newMessage.createdAt
            }
        });

    } catch (error) {
        console.error("❌ Send Message Error:", error);
        console.error("Stack trace:", error.stack);
        res.status(500).json({ message: "Failed to send message" });
    }
};

exports.getMessages = async (req, res) => {
    try {
        console.log("📥 Starting get messages process...");
        
        const { conversationId } = req.params;
        
        // Get userId from JWT token (you need to implement JWT middleware)
        // For now, we'll accept it from request body as fallback
        let userId = req.user?.id || req.user?.userId || req.body.userId;
        
        console.log("📝 Get messages request:", {
            conversationId,
            userId,
            hasReqUser: !!req.user
        });

        if (!conversationId) {
            console.log("❌ Missing conversation ID");
            return res.status(400).json({ message: "Conversation ID is required" });
        }

        if (!userId) {
            console.log("❌ Missing user ID");
            return res.status(400).json({ message: "User authentication required" });
        }

        console.log("🔍 Finding user and private key...");
        
        // Get user's private key from database
        const user = await User.findById(userId).select('+privateKey');
        
        console.log("📊 User lookup result:", {
            userFound: !!user,
            hasPrivateKey: !!user?.privateKey
        });

        if (!user || !user.privateKey) {
            console.log("❌ User or private key not found");
            return res.status(400).json({ message: "User authentication failed or encryption key missing" });
        }

        console.log("🔍 Verifying conversation access...");
        
        // Verify user is part of this conversation
        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
            console.log("❌ Conversation not found");
            return res.status(404).json({ message: "Conversation not found" });
        }

        if (!conversation.participants.includes(userId)) {
            console.log("❌ User not part of conversation");
            return res.status(403).json({ message: "Access denied to this conversation" });
        }

        console.log("✅ User verified as conversation participant");

        console.log("🔍 Fetching messages...");
        
        const messages = await Message.find({ conversationId })
            .sort({ createdAt: 1 })
            .populate("sender", "username")
            .populate("receiver", "username");

        console.log("📊 Messages found:", messages.length);

        console.log("🔓 Decrypting messages...");
        
        const decryptedMessages = messages.map((msg, index) => {
            console.log(`🔓 Decrypting message ${index + 1}/${messages.length}...`);
            
            let decrypted;
            try {
                // Decrypt based on whether user is sender or receiver
                if (msg.sender._id.toString() === userId) {
                    console.log("👤 User is sender, using encryptedForSender");
                    decrypted = decryptMessage(msg.encryptedForSender, user.privateKey);
                } else {
                    console.log("👤 User is receiver, using encryptedForReceiver");
                    decrypted = decryptMessage(msg.encryptedForReceiver, user.privateKey);
                }
                console.log("✅ Message decrypted successfully");
            } catch (err) {
                console.error(`❌ Decryption error for message ${msg._id}:`, err);
                decrypted = "[Unable to decrypt message]";
            }
            
            return {
                _id: msg._id,
                sender: msg.sender.username,
                receiver: msg.receiver.username,
                text: decrypted,
                isRead: msg.isRead,
                createdAt: msg.createdAt,
                isSentByMe: msg.sender._id.toString() === userId
            };
        });

        console.log("✅ All messages processed");

        res.status(200).json({
            success: true,
            count: decryptedMessages.length,
            messages: decryptedMessages
        });

    } catch (error) {
        console.error("❌ Get Messages Error:", error);
        console.error("Stack trace:", error.stack);
        res.status(500).json({ message: "Failed to fetch messages" });
    }
};

// Helper function to get messages by conversation ID (alternative endpoint)
exports.getMessagesByConversation = async (req, res) => {
    try {
        console.log("📥 Alternative get messages endpoint...");
        
        const { conversationId, userId } = req.body;
        
        console.log("📝 Request details:", {
            conversationId,
            userId
        });

        if (!conversationId || !userId) {
            console.log("❌ Missing required fields");
            return res.status(400).json({ message: "Conversation ID and User ID are required" });
        }

        console.log("🔍 Finding user and private key...");
        
        // Get user's private key from database
        const user = await User.findById(userId).select('+privateKey');
        
        if (!user || !user.privateKey) {
            console.log("❌ User or private key not found");
            return res.status(400).json({ message: "User authentication failed or encryption key missing" });
        }

        console.log("🔍 Verifying conversation access...");
        
        // Verify user is part of this conversation
        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
            console.log("❌ Conversation not found");
            return res.status(404).json({ message: "Conversation not found" });
        }

        if (!conversation.participants.includes(userId)) {
            console.log("❌ User not part of conversation");
            return res.status(403).json({ message: "Access denied to this conversation" });
        }

        console.log("✅ User verified as conversation participant");

        console.log("🔍 Fetching messages...");
        
        const messages = await Message.find({ conversationId })
            .sort({ createdAt: 1 })
            .populate("sender", "username")
            .populate("receiver", "username");

        console.log("📊 Messages found:", messages.length);

        console.log("🔓 Decrypting messages...");
        
        const decryptedMessages = messages.map((msg, index) => {
            console.log(`🔓 Decrypting message ${index + 1}/${messages.length}...`);
            
            let decrypted;
            try {
                // Decrypt based on whether user is sender or receiver
                if (msg.sender._id.toString() === userId) {
                    console.log("👤 User is sender, using encryptedForSender");
                    decrypted = decryptMessage(msg.encryptedForSender, user.privateKey);
                } else {
                    console.log("👤 User is receiver, using encryptedForReceiver");
                    decrypted = decryptMessage(msg.encryptedForReceiver, user.privateKey);
                }
                console.log("✅ Message decrypted successfully");
            } catch (err) {
                console.error(`❌ Decryption error for message ${msg._id}:`, err);
                decrypted = "[Unable to decrypt message]";
            }
            
            return {
                _id: msg._id,
                sender: msg.sender.username,
                receiver: msg.receiver.username,
                text: decrypted,
                isRead: msg.isRead,
                createdAt: msg.createdAt,
                isSentByMe: msg.sender._id.toString() === userId
            };
        });

        console.log("✅ All messages processed");

        res.status(200).json({
            success: true,
            count: decryptedMessages.length,
            messages: decryptedMessages
        });

    } catch (error) {
        console.error("❌ Get Messages Error:", error);
        console.error("Stack trace:", error.stack);
        res.status(500).json({ message: "Failed to fetch messages" });
    }
};