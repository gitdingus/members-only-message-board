const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const messageSchema = new Schema({
  author: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now(),
    required: true,
  },
  title: {
    type: String,
    required: true,
    trim: true,
    minLength: 1,
    maxLength: 50,
  },
  body: {
    type: String,
    required: true,
    trim: true,
    minLength: 1,
    maxLength: 500,
  }
});

messageSchema.virtual('url').get(function () {
  return `/messages/${this._id}`;
});

module.exports = mongoose.model('Message', messageSchema);