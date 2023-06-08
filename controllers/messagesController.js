const express = require('express');
const passport = require('passport');
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const Message = require('../models/message.js');

exports.get_create_message = (req, res, next) => {
  if (req.isAuthenticated() === true) {
    res.render('message_form', {
      title: 'Create Message',
      user: req.user,
    });
    return;
  } else {
    res.send('Access Denied');
    return;
  }
};

exports.post_create_message = [
  express.json(),
  express.urlencoded({ extended: false }),
  body('title', 'Title must be between 1 and 50 characters')
    .trim()
    .isLength({ min: 1, max: 50 })
    .escape(),
  body('body', 'Body must be between 1 and 500 characters')
    .trim()
    .isLength({ min: 1, max: 500 })
    .escape(),
  asyncHandler(async(req, res, next) => {
    if (req.isAuthenticated() === false) {
      res.send('Unauthorized');
      return;
    }
    const errors = validationResult(req);
    const message = new Message({
      title: req.body.title,
      body: req.body.body,
    });

    if (!errors.isEmpty()) {
      res.render('message_form', {
        title: 'Create Message',
        user: req.user,
        message: message,
        errors: errors.array(),
      });
      return;
    }

    message.author = req.user._id;
    await message.save();

    res.redirect('/');
  }),
];