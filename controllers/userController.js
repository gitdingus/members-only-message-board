const express = require('express');
const asyncHandler = require('express-async-handler');
const createError = require('http-errors');
const { body, validationResult } = require('express-validator');
const User = require('../models/user.js');
const Message = require('../models/message.js');

const isLoggedInUser = (req, res, next) => {
  if (req.isAuthenticated()) {
    if (req.user.username !== req.params.username) {
      const err = createError(403, 'Forbidden');
      return next(err);
    }
  } else {
    const err = createError(401, 'Unauthorized');
    return next(err);
  }

  next();
};

exports.get_user_details = asyncHandler(async (req, res, next) => {
  const privledgedUsers = ['Admin', 'Member'];

  if (req.isAuthenticated()) {
    if (!(privledgedUsers.includes(req.user.memberStatus) 
      || req.user.username === req.params.username)) {
        const err = createError(403, 'Forbidden');
        return next(err);
    }
  } else {
    const err = createError(401, 'Unauthorized');
    return next(err);
  }

  const user = await User
    .findOne({ username: req.params.username })
    .select({ salt: 0, hash: 0 })
    .exec();

  if (user === null) {
    const err = createError(404, 'User not found');
    return next(err);
  }
  
  const messages = await Message.find({ author: user._id }).exec(); 
  const restrictedFields = ['firstName', 'lastName', 'email'];
  const isAdmin = req.user.memberStatus === 'Admin';
  const isUsersOwnProfile = req.user.username === req.params.username;

  if (isUsersOwnProfile === false && user.publicProfile !== true) {
    restrictedFields.forEach((field) => {
      user[field] = undefined;
    });
  }

  res.render('user_detail', {
    title: `Profile - ${user.username}`,
    user: req.user,
    userInfo: user,
    messages,
    isUsersOwnProfile,
    isAdmin,
  });

});

exports.get_update_info = [
  isLoggedInUser,
  asyncHandler(async(req, res, next) => {
    const user = await User.findOne({ username: req.params.username }).exec();

    if (user === null) {
      const err = createError(404, 'User not found');
      return next(err);
    }

    res.render('update_personal_info', {
      title: 'Update Personal Info',
      userMod: req.user,
      user: req.user,
    });
  }),
];

exports.post_update_info = [
  isLoggedInUser,
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
  body('email', 'Must supply valid email address')
    .trim()
    .escape()
    .isEmail()
    .custom(async (requestedEmail, { req }) => {
      const user = await User.findOne({ email: requestedEmail }, 'email');

      // if email exists and not logged in users THROW ERROR
      // returning falsey value with async function does not work.
      if (user._id.toString() !== req.user._id.toString()) {
        throw new Error();
      }

      return true;
    }).withMessage('An account is already associated with this email address'),
  asyncHandler(async(req, res, next) => {
    const errors = validationResult(req);
    const userMod = {
      firstName: req.body.first_name,
      lastName: req.body.last_name,
      email: req.body.email,
    }
    if (!errors.isEmpty()) {
      res.render('update_personal_info', {
        title: 'Update Personal Info',
        user: req.user,
        userMod: userMod,
        errors: errors.array(),
      });
      return; 
    }

    await User.findByIdAndUpdate(req.user._id, userMod);
    res.redirect(req.user.url);
  }),
];

exports.get_change_password = (req, res, next) => {
  res.send('GET CHANGE PASSWORD: Not implemented');
};

exports.post_change_password = (req, res, next) => {
  res.send('POST CHANGE PASSWORD: Not implemented');
};

exports.get_account_settings = (req, res, next) => {
  res.send('GET ACCOUNT SETTINGS: Not implemented');
};

exports.post_account_settings = (req, res, next) => {
  res.send('POST ACCOUNT SETTINGS: Not implemented');
};

exports.get_membership_status = (req, res, next) => {
  res.send('GET MEMBERSHIP STATUS: Not implemented');
};

exports.post_membership_status = (req, res, next) => {
  res.send('POST MEMBERSHIP STATUS: Not implemented');
};

exports.get_delete_account = (req, res, next) => {
  res.send('GET DELETE ACCOUNT: Not implemented');
};

exports.post_delete_account = (req, res, next) => {
  res.send('POST DELETE ACCOUNT: Not implemented');
};