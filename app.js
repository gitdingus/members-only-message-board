if (process.env.MODE !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-localstrategy');
const configPassportLocalStrategy = require('./utils/configLocalStrategy.js');
const authRouter = require('./routes/authentication-routes');
const User = require('./models/user.js');
const { validPassword } = require('./utils/passwordUtils.js');

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

configPassportLocalStrategy(passport, LocalStrategy);

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

app.use(authRouter);

app.get('/', (req, res, next) => res.render('index'));

app.listen(3000, () => {
  console.log('Listening on port 3000');
});