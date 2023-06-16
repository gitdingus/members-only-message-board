const express = require('express');
const userController = require('../controllers/userController.js');

const userRouter = express.Router();

userRouter.use('/:username', userController.get_user_details);

module.exports = userRouter;