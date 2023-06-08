const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const secretSchema = new Schema({
  secret: {
    type: String,
    required: true,
  }
});

module.exports = mongoose.model('Secret', secretSchema);