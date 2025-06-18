const express = require("express");
const router = express.Router();
const conversationController = require("../controller/conversationcontroller");

// Get all conversations for a user
router.get("/:userId", conversationController.getUserConversations);

module.exports = router;
