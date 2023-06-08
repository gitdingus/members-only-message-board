const express = require('express');
const messageController = require('../controllers/messagesController.js');
const Message = require('../models/message.js');

const messageRouter = express.Router();

messageRouter.get('/create', messageController.get_create_message);
messageRouter.post('/create', messageController.post_create_message);
module.exports = messageRouter;