require('dotenv').config();

const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const asyncHandler = require('express-async-handler');
const createError = require('http-errors');
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
    maxAge: 1000 * 60 * 30, // 30 minutes 
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
    const messageQuery = Message.find({}, 'title');
    const privledgedUsers = ['Admin', 'Member'];

    if (req.isAuthenticated() && privledgedUsers.includes(req.user.memberStatus)) {
      messageQuery 
        .select('timestamp author')
        .populate('author', 'username');
    }

    const messages = await messageQuery.exec();
    
    res.render('index', {
      user: req.user,
      messages: messages,
    });  
  }),
);

app.use((req, res, next) => {
  next(createError(404, 'File not found'));
});

app.use((err, req, res, next) => {
  // FIX THIS MAKE SURE IT HANDLES 
  // INTERNAL ERRORS
  err.status = err.status || 500;

  if (process.env.NODE_ENV === 'production') {
    if (err.status == 500) {
      err.message = 'Internal Server Error';
    }

    err.stack = '';
  }

  res.status(err.status);
  res.render('error', {
    message: `${err.status} - ${err.message}`,
    stack: err.stack,
  });
})

app.listen(process.env.PORT, () => {
  console.log(`Listening on port ${process.env.PORT}`);
});