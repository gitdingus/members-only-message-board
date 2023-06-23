const express = require('express');
const asyncHandler = require('express-async-handler');
const createError = require('http-errors');
const { body, validationResult } = require('express-validator');
const User = require('../models/user.js');
const Message = require('../models/message.js');
const Secret = require('../models/secret.js');
const { validPassword, generateSaltHash, passwordConfig } = require('../utils/passwordUtils.js');

const isAdmin = (req, res, next) => {
  if (req.isAuthenticated()) {
    if (req.user.memberStatus !== 'Admin') {
      const err = createError(403, 'Forbidden');
      return next(err);
    }
  } else {
    const err = createError(401, 'Unauthorized');
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

exports.get_user_details = [
  isNotBanned,
  asyncHandler(async (req, res, next) => {
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

    const skip = Number.parseInt(req.query.skip) || 0;
    const limit = 10;

    const prevResults = (skip > 0) ? `${req.baseUrl}?skip=${skip - limit}` : null;
    const nextResults = `${req.baseUrl}?skip=${skip + limit}`;

    const user = await User
      .findOne({ username: req.params.username })
      .select({ salt: 0, hash: 0 })
      .exec();

    if (user === null) {
      const err = createError(404, 'User not found');
      return next(err);
    }
    
    const messages = await Message
      .find({ author: user._id })
      .skip(skip)
      .limit(limit)
      .exec(); 

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
      prevPage: prevResults,
      nextPage: nextResults,
      isUsersOwnProfile,
      isAdmin,
    });
  }),
];

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

exports.get_change_password = [
  isLoggedInUser,
  asyncHandler(async(req, res, next) => {
    res.render('change_password', {
      title: 'Change Password',
      user: req.user,
    });
  }),
];

exports.post_change_password = [
  isLoggedInUser,
  express.json(),
  express.urlencoded({ extended: false }),
  body('current_password', 'Invalid Password')
    .custom(async (val, { req }) => {
      const currentUser = await User.findById(req.user._id, 'salt hash').exec();

      if (!validPassword(val, currentUser.salt, currentUser.hash)) {
        throw new Error();
      }
    }),
  body('new_password', 'Password must be at least 5 characters')
    .isStrongPassword(passwordConfig), // MAKE STRONGER IN PROD
  body('confirm_new_password', 'Passwords do not match')
    .custom((val, { req }) => {
      return val === req.body.new_password;
    }),
  asyncHandler(async(req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      res.render('change_password', {
        title: 'Change Password',
        user: req.user,
        errors: errors.array(),
      });
      return;
    }

    const saltHash = generateSaltHash(req.body.new_password);

    await User.findByIdAndUpdate(req.user._id, {
      salt: saltHash.salt,
      hash: saltHash.hash,
    });

    res.render('change_password', {
      title: 'Change Password',
      user: req.user,
      message: 'Password changed successfully',
    });
  },)
];

exports.get_account_settings = [
  isLoggedInUser,
  asyncHandler(async(req, res, next) => {
    const userProfileStatus = await User.findById(req.user._id, 'publicProfile').exec();

    res.render('account_settings', {
      title: 'Update Account Settings',
      user: req.user,
      publicProfile: userProfileStatus.publicProfile,
    });
  }),
];

exports.post_account_settings = [
  isLoggedInUser,
  express.json(),
  express.urlencoded({ extended: false }),
  asyncHandler(async(req, res, next) => {
    const updateObj = {
      publicProfile: (req.body.profile_type === 'public') ? true : false,
    };

    await User.findByIdAndUpdate(req.user._id, updateObj);
    res.redirect(req.user.url);
  }),
];

exports.get_membership_status = [
  isLoggedInUser,
  asyncHandler(async(req, res, next) => {
    res.render('membership_status', {
      user: req.user,
      title: 'Membership Status',
    });
  }),
];

exports.post_membership_status = [
  isLoggedInUser,
  express.json(),
  express.urlencoded({ extended: false }),
  asyncHandler(async (req, res, next) => {
    const secret = await Secret.findOne({ secret: req.body.member_password }).exec();
    
    if (secret === null) {
      res.render('membership_status', {
        user: req.user,
        title: 'Membership Status',
        message: 'Sorry, that is not a valid password',
      });
      return;
    } else {
      await User.findByIdAndUpdate(req.user._id, {
        memberStatus: 'Member',
      });

      res.redirect(req.user.url);
    }
  }),
];

exports.get_delete_account = [
  isLoggedInUser,
  asyncHandler(async(req, res, next) => {
    res.render('delete_account', {
      title: 'Delete Account',
      user: req.user,
    });
  }),
];

exports.post_delete_account = [
  isLoggedInUser,
  express.json(),
  express.urlencoded({ extended: false }),
  asyncHandler(async(req, res, next) => {
    const userId = req.user._id;

    if (req.body.delete_account === 'delete') {
      req.logout(async function (err) {
        if (err) {
          return next(err);
        }
        await User.findByIdAndDelete(userId);
        res.redirect('/');
      });

      return;
    } else {
      res.render('delete_account', {
        title: 'Delete Account',
        user: req.user,
        errors: [{ msg: 'Must check Delete Account to delete your account' }],
      });
    }
    
  }),
];

exports.get_admin_delete_user_messages = [
  isAdmin,
  asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id, 'username').exec();
    const messages = await Message.find({ author: req.params.id }).exec();
  
    res.render('admin_delete_user_messages', {
      user: req.user,
      userInfo: user,
      title: 'Admin - Delete User Messages',
      messages: messages,
    });
  }),
];

exports.post_admin_delete_user_messages = [
  isAdmin,
  express.json(),
  express.urlencoded({ extended: false }),
  asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id, 'username').exec();
    const messages = await Message.find({ author: req.params.id }).exec();
  
    if (req.body.delete_messages !== 'delete') {
      res.render('admin_delete_user_messages', {
        user: req.user,
        userInfo: user,
        title: 'Admin - Delete User Messages',
        messages: messages,
        errors: [{ msg: 'Must check box to delete messages'}],
      });
      return;
    } else {
      const deleteMessages = await Message.deleteMany({ author: req.params.id }).exec();
      res.redirect(user.url);
    }
  }),
];

exports.get_admin_set_user_status = [
  isAdmin,
  asyncHandler(async(req, res, next) => {
    const user = await User.findById(req.params.id, 'username memberStatus').exec();
    const statuses = Array.from(User.schema.obj.memberStatus.enum);

    res.render('admin_set_user_status', {
      user: req.user,
      title: 'Set User Status',
      userInfo: user,
      statuses: statuses,
    })
    return;
  }),
];

exports.post_admin_set_user_status = [
  isAdmin,
  express.json(),
  express.urlencoded({ extended: true }),
  asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id).exec();
    const newStatus = {
      memberStatus: req.body.status,
    };

    await User.findByIdAndUpdate(req.params.id, newStatus);
    res.redirect(user.url);
  }),
];

exports.get_admin_delete_user = [
  isAdmin,
  asyncHandler(async(req, res, next) => {
    const user = await User.findById(req.params.id).exec();

    res.render('admin_delete_user', {
      user: req.user,
      title: 'Delete User',
      userInfo: user,
    });
    return;
  }),
];

exports.post_admin_delete_user = [
  isAdmin,
  express.json(),
  express.urlencoded({ extended: false }),
  asyncHandler(async(req, res, next) => {
    const user = await User.findById(req.params.id).exec();
    const { delete_user, delete_messages } = req.body;

    if (user === null) {
      const err = createError(404, 'User not found')
      return next(err);
    }
    if (delete_user !== 'delete') {
      res.render('admin_delete_user', {
        user: req.user,
        title: 'Delete User',
        userInfo: user,
        errors: [{ msg: 'Must select delete user to proceed' }],
      });
      return;
    } else {
      if (delete_messages === 'delete') {
        await Message.deleteMany({ author: req.params.id });
      }

      await User.findByIdAndDelete(req.params.id);

      res.redirect('/');
    }
  }),
];
