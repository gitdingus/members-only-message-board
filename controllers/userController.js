const asyncHandler = require('express-async-handler');
const createError = require('http-errors');
const User = require('../models/user.js');
const Message = require('../models/message.js');

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
    user: req.user,
    userInfo: user,
    messages,
    isUsersOwnProfile,
    isAdmin,
  });

});