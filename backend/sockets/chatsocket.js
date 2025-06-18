const { encryptMessage, decryptMessage } = require("../utils/crypto");
const Message = require("../databasemodels/messagemodel");
const Conversation = require("../databasemodels/conversationmodel");
const User = require("../databasemodels/usermodel");

module.exports = (io) => {
    io.on("connection", (socket) => {
        console.log("User connected:", socket.id);

        socket.on("sendMessage", async ({ senderId, receiverId, message }) => {
            try {
                const receiver = await User.findById(receiverId);
                if (!receiver) return;

                const encryptedMessage = encryptMessage(message, receiver.identityKey);

                let conversation = await Conversation.findOne({
                    participants: { $all: [senderId, receiverId] },
                });

                if (!conversation) {
                    conversation = await Conversation.create({
                        participants: [senderId, receiverId],
                    });
                }

                const newMessage = await Message.create({
                    conversationId: conversation._id,
                    sender: senderId,
                    receiver: receiverId,
                    encryptedMessage,
                });

                conversation.lastMessage = newMessage._id;
                await conversation.save();

                io.to(receiverId).emit("receiveMessage", {
                    senderId,
                    encryptedMessage: newMessage.encryptedMessage,
                });
            } catch (err) {
                console.error("Socket Message Error:", err);
            }
        });

        socket.on("disconnect", () => {
            console.log("User disconnected:", socket.id);
        });
    });
};


