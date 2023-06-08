const express = require('express');
const passport = require('passport');
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const Message = require('../models/message.js');
const getDeleteDebug = require('debug')('messageController:getDelete');

exports.get_message_detail = asyncHandler(async (req, res, next) => {
  let projection = 'title body';
  const messageQuery = Message.findById(req.params.id).select('title body');
  const privledgedUsers = ['Admin', 'Member'];
  if (req.isAuthenticated() === true && privledgedUsers.includes(req.user.memberStatus) === true) {
    messageQuery
      .select('author timestamp')
      .populate('author', 'username');
  }

  const message = await messageQuery.exec();

  res.render('message_detail', {
    title: 'View Message',
    message: message,
    user: req.user,
  });
});

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

exports.get_delete_message = asyncHandler(async(req, res, next) => {
  getDeleteDebug(`Authenticated: ${req.isAuthenticated()}`);
  getDeleteDebug(`Member Status: ${req.user.memberStatus}`);
  if (!(req.isAuthenticated() && req.user.memberStatus === 'Admin')) {
    res.send('Unauthorized');
    return;
  }

  const message = await Message.findById(req.params.id);

  res.render('message_delete', {
    title: 'Delete Message',
    user: req.user,
    message: message,
  });
  return;
});

exports.post_delete_message = asyncHandler(async(req, res, next) => {
  if (!(req.isAuthenticated() && req.user.memberStatus === 'Admin')) {
    res.send('Unauthorized');
    return;
  }

  await Message.findByIdAndDelete(req.params.id);
  res.redirect('/');
});