if (process.env.MODE !== 'production') {
  require('dotenv').config();
}

const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const asyncHandler = require('express-async-handler');
const authRouter = require('./routes/authentication-routes');
const messageRouter = require('./routes/message-routes.js');
const User = require('./models/user.js');
const Message = require('./models/message.js');

connectMongo()
  .then(() => console.log('Connected to Database'))
  .catch(err => console.log(err));

async function connectMongo() {
  await mongoose.connect(process.env.MONGO_CONNECTION_STRING);
}

const app = express();

app.set('view engine', 'pug');
app.set('views', './views');

const mongoStore = MongoStore.create({
  mongoUrl: process.env.MONGO_CONNECTION_STRING,
  collectionName: 'sessions',
});

require('./utils/configPassportLocalStrategy.js');

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    maxAge: 1000 * 60 * 5, // 5 minutes 
  },
  resave: false,
  saveUninitialized: false,
  store: mongoStore,
}));
app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, 'public')));

app.use(authRouter);
app.use('/messages', messageRouter);

app.get('/',
  asyncHandler(async(req, res, next) => {
    const messages = await Message.find({}, 'title').exec();

    res.render('index', {
      user: req.user,
      messages: messages,
    });  
  }),
);

app.listen(3000, () => {
  console.log('Listening on port 3000');
});