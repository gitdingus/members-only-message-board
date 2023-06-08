const express = require('express');
const authController = require('../controllers/authenticationController.js');

const authRouter = express.Router()

authRouter.get('/register', authController.get_register);
authRouter.post('/register', authController.post_register);

authRouter.post('/login', authController.post_login)
authRouter.get('/logout', authController.get_logout);
module.exports = authRouter;
