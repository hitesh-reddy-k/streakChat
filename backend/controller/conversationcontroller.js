const Conversation = require("../databasemodels/conversationmodel");
const User = require("../databasemodels/usermodel");

exports.getUserConversations = async (req, res) => {
    try {
        const { userId } = req.params;

        const conversations = await Conversation.find({ participants: userId })
            .populate("participants", "username")
            .populate({
                path: "lastMessage",
                select: "encryptedMessage sender receiver createdAt",
                populate: [
                    { path: "sender", select: "username" },
                    { path: "receiver", select: "username" }
                ]
            })
            .sort({ updatedAt: -1 });

        res.status(200).json(conversations);
    } catch (error) {
        console.error("Get Conversations Error:", error);
        res.status(500).json({ message: "Failed to fetch conversations" });
    }
};
