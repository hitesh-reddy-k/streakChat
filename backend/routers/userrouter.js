const express = require('express');
const bodyParser = require('body-parser');

const path = require("path")



const { registerUser,verifyOtp,loginUser } = require('../controller/usercontroller');

const router = express.Router();





router.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "..","..", "forentend", "registration", "sign-up.html"));
});


router.post('/register', registerUser);

router.post('/verify-otp', verifyOtp);

router.post('/login', loginUser);

module.exports = router;