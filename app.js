if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const asyncHandler = require('express-async-handler');
const createError = require('http-errors');
const morgan = require('morgan');
const authRouter = require('./routes/authentication-routes');
const messageRouter = require('./routes/message-routes.js');
const userRouter = require('./routes/user-routes');
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

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else if (process.env.NODE_ENV === 'production') {
  app.use(morgan('common'));
}

app.use(express.static(path.join(__dirname, 'public')));

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

app.use(authRouter);
app.use('/messages', messageRouter);
app.use('/users', userRouter);

app.get('/',
  (req, res, next) => { // Check if user is banned
    if (req.isAuthenticated()) {
      if (req.user.memberStatus === 'Banned') {
        const err = createError(403, 'Forbidden');
        return next(err);
      }
    } // Doesn't handle unauthenticated requests.
    next();
  },
  asyncHandler(async(req, res, next) => {
    const messageQuery = Message.find({}, 'title');
    const privledgedUsers = ['Admin', 'Member'];

    const skip = Number.parseInt(req.query.skip) || 0;
    const limit = 10;

    const prevResults = (skip > 0) ? `${req.path}?skip=${skip - limit}` : null;
    const nextResults = `${req.path}?skip=${skip + limit}`;

    if (req.isAuthenticated() && privledgedUsers.includes(req.user.memberStatus)) {
      messageQuery 
        .select('timestamp author')
        .populate('author', 'username');
    }

    const messages = await messageQuery
      .sort({timestamp: 'desc'})
      .skip(skip)
      .limit(limit)
      .exec();

    res.render('index', {
      user: req.user,
      messages: messages,
      prevPage: prevResults,
      nextPage: nextResults,
      loginAttempt: failedLoginAttempt(req.session.messages) ? 'Invalid username/password' : null,
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
    user: req.user,
    message: `${err.status} - ${err.message}`,
    stack: err.stack,
  });
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});

function failedLoginAttempt(messages) {
  if (!Array.isArray(messages)) {
    return false;
  }

  for (let i = 0; i < messages.length; i+= 1) {
    if (messages[i] === 'invalid-login-attempt') {
      return true;
    }
  }

  return false;
}