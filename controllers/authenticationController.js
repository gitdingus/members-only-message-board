const passport = require('passport');
const express = require('express');
const post_register_debug = require('debug')('auth:post_register');
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const User = require('../models/user.js');
const Secret = require('../models/secret.js');
const { generateSaltHash } = require('../utils/passwordUtils.js');

const passwordConfig = { 
  // Make stronger in prod
  minLength: 5,
  minLowercase: 0,
  minUppercase: 0,
  minNumbers: 0,
  minSymbols: 0,
  returnScore: false,
};

exports.get_register = (req, res, next) => {
  res.render('register_form', {
    title: 'Register',
  });
};

exports.post_register = [
  express.json(),
  express.urlencoded({ extended: false }),
  body('first_name', 'Must supply first name')
    .trim()
    .isLength({ min: 1 })
    .escape(),
  body('last_name', 'Must supply last name')
    .trim()
    .isLength({ min: 1 })
    .escape(),
  body('username', 'Must supply username')
    .trim()
    .isLength({ min: 1 })
    .escape()
    .custom(async (requestedUsername) => {
      const user = await User.findOne({ username: requestedUsername }, 'username');
      
      // if username exists THROW ERROR
      // returning falsey values with async function does not work.
      if (user !== null) {
        throw new Error();
      }
    }).withMessage('Username is already in use'),
  body('email', 'Must supply valid email address')
    .trim()
    .escape()
    .isEmail()
    .custom(async (requestedEmail) => {
      const user = await User.findOne({ email: requestedEmail }, 'email');

      // if email exists THROW ERROR
      // returning falsey value with async function does not work.
      if (user !== null) {
        throw new Error();
      }
    }).withMessage('An account is already associated with this email address'),
  body('password', 'Password must be at least 5 characters')
    .isStrongPassword(passwordConfig), // MAKE STRONGER IN PROD
  body('confirm_password', 'Passwords do not match')
    .custom((val, { req }) => {
      return val === req.body.password;
    }),
  asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    const newUser = new User({
      firstName: req.body.first_name,
      lastName: req.body.last_name,
      username: req.body.username,
      email: req.body.email,
    });

    if (!errors.isEmpty()) {
      post_register_debug('Errors in user sign up');
      res.render('register_form', {
        title: 'Register',
        errors: errors.array(),
        newUser: newUser,
      });
      post_register_debug('Returning without redirect');
      return;
    }

    const { salt, hash } = generateSaltHash(req.body.password);
    newUser.salt = salt;
    newUser.hash = hash;
    

    const secret = await Secret.findOne({ secret: req.body.member_password || '' });
    
    if (secret !== null) {
      newUser.memberStatus = 'Member';
    } else {
      newUser.memberStatus = 'User';
    }

    await newUser.save();

    res.redirect('/');
  }),
];

exports.post_login = [
  express.json(),
  express.urlencoded({ extended: false }),
  passport.authenticate('local', { successRedirect: '/', failureRedirect: '/' }),
];

exports.get_logout = (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
}