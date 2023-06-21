const mongoose = require('mongoose');
const validator = require('validator');
const Schema = mongoose.Schema;

const userSchema = new Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,
    minLength: 1,
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    minLength: 1,
  },
  username: {
    type: String,
    required: true,
    trim: true,
    minLength: 1,
  },
  email: {
    type: String,
    required: true,
    trim: true,
    validate: {
      validator: validator.isEmail,
      message: 'Invalid email address encountered during user validation',
    }
  },
  salt: {
    type: String,
    required: true,
    trim: true,
    minLength: 32,
  },
  hash: {
    type: String,
    required: true,
    trim: true,
    minLength: 128,
  },
  memberStatus: {
    type: String,
    required: true,
    enum: [ 'Member', 'User', 'Admin', 'Restricted', 'Banned' ],
  },
  publicProfile: Boolean,
});

userSchema.virtual('url').get(function () {
  return `/users/${this.username}`;
});

userSchema.virtual('adminUrl').get(function () {
  return `/users/${this._id}/admin`;
})

module.exports = mongoose.model('User', userSchema);