const mongoose = require("mongoose");
const dotenv = require('dotenv');


dotenv.config({ path: "backend/envfile/config.env" });

const URL = process.env.URL 
console.log(URL)

const Connect = async () => {
    try {
        await mongoose.connect(URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            connectTimeoutMS: 30000, 
            socketTimeoutMS: 45000,
        });
        console.log(`MongoDB connected successfully: ${URL}`);
    } catch (error) {
        console.error(`MongoDB connection error: ${error.message}`);
        
    }
};

module.exports = Connect;
