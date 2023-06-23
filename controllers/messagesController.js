const express = require('express');
const passport = require('passport');
const asyncHandler = require('express-async-handler');
const createError = require('http-errors');
const { body, validationResult } = require('express-validator');
const Message = require('../models/message.js');
const getDeleteDebug = require('debug')('messageController:getDelete');

const adminOnly = (req, res, next) => {
  if (req.isAuthenticated()) {
    if (req.user.memberStatus !== 'Admin') {
      const err = createError(403, 'Forbidden');
      return next(err);
    }
  } else {
    const err = createError(401, 'Not authorized');
    return next(err);
  }

  next();
}

const isNotBannedOrRestricted = (req, res, next) => {
  const bannedOrRestricted = [ 'Banned', 'Restricted' ];

  if (req.isAuthenticated()) {
    if (bannedOrRestricted.includes(req.user.memberStatus)) {
      const err = createError(403, 'Forbidden');
      return next(err);
    }
  } // Doesn't handle unauthenticated requests.

  next();
}

const isNotBanned = (req, res, next) => {
  if (req.isAuthenticated()) {
    if (req.user.memberStatus === 'Banned') {
      const err = createError(403, 'Forbidden');
      return next(err);
    }
  } // Doesn't handle unauthenticated requests.
  next();
}

exports.get_message_detail = [
  isNotBanned,
  asyncHandler(async (req, res, next) => {
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
  }),
]

exports.get_create_message = [
  isNotBannedOrRestricted,
  asyncHandler(async (req, res, next) => {
    if (req.isAuthenticated() === false) {
      const err = createError(401, 'Unauthorized');
      return next(err);
    }

    res.render('message_form', {
      title: 'Create Message',
      user: req.user,
    });
  }),
];

exports.post_create_message = [
  isNotBannedOrRestricted,
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
      const err = createError(401, 'Unauthorized');
      return next(err);
    }

    const errors = validationResult(req);
    const message = new Message({
      title: req.body.title,
      body: req.body.body,
      timestamp: Date.now(),
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

exports.get_delete_message = [
  adminOnly,
  asyncHandler(async(req, res, next) => {
    getDeleteDebug(`Authenticated: ${req.isAuthenticated()}`);
    if (req.isAuthenticated()) {
      getDeleteDebug(`Member Status: ${req.user.memberStatus}`);
    } 

    const message = await Message.findById(req.params.id).populate('author', 'username');

    res.render('message_delete', {
      title: 'Delete Message',
      user: req.user,
      message: message,
    });
    return;
  })
];

exports.post_delete_message = [
  adminOnly,
  asyncHandler(async(req, res, next) => {
    await Message.findByIdAndDelete(req.params.id);
    res.redirect('/');
  })
];