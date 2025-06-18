const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../utilites/jwt');
const messageController = require('../controller/messagecontroller');

// Debug route to test authentication
router.get('/test-auth', authenticateToken, (req, res) => {
    console.log("🧪 Test auth route accessed");
    res.json({ 
        message: "Authentication working", 
        user: req.user 
    });
});

// Send message (requires authentication)
router.post('/send', authenticateToken, messageController.sendMessage);

// Get messages by conversation ID (requires authentication)
router.get('/conversation/:conversationId', authenticateToken, messageController.getMessages);

// Alternative endpoint: Get messages with conversation ID in body
router.post('/get-messages', authenticateToken, messageController.getMessagesByConversation);

// Alternative endpoint without JWT (for testing - remove in production)
router.post('/get-messages-simple', messageController.getMessagesByConversation);

module.exports = router;