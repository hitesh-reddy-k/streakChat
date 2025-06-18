const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const http = require('http');
const connect = require("../backend/databaseconnect/database")
const registerrouter = require('./routers/userrouter');
const path = require('path');
const dotenv = require('dotenv');
const conversationrouter = require('../backend/routers/conversationrouter');
const messagerouter = require('../backend/routers/messagerouter');

dotenv.config({ path: path.join(__dirname, "envfile", "config.env") });

const app = express();
app.use(bodyParser.json());

app.use(express.json());

app.use("/user", registerrouter);
app.use("/conversation", conversationrouter);
app.use("/message", messagerouter);



connect();

const PORT = process.env.PORT || 9999;
const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`);
});

