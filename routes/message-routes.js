const express = require('express');
const messageController = require('../controllers/messagesController.js');
const Message = require('../models/message.js');

const messageRouter = express.Router();

messageRouter.get('/create', messageController.get_create_message);
messageRouter.post('/create', messageController.post_create_message);
messageRouter.get('/:id', messageController.get_message_detail);
messageRouter.get('/:id/delete', messageController.get_delete_message);
messageRouter.post('/:id/delete', messageController.post_delete_message);

module.exports = messageRouter;