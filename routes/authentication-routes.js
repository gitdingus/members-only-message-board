const express = require('express');
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const User = require('../models/user.js');
const authController = require('../controllers/authenticationController.js');

const authRouter = express.Router();

authRouter.get('/register', authController.get_register);
authRouter.post('/register', authController.post_register);

module.exports = authRouter;
