if (process.env.MODE !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const mongoose = require('mongoose');
const authRouter = require('./routes/authentication-routes');

connectMongo()
  .then(() => console.log('Connected to Database'))
  .catch(err => console.log(err));

async function connectMongo() {
  await mongoose.connect(process.env.MONGO_CONNECTION_STRING);
}

const app = express();

app.set('view engine', 'pug');
app.set('views', './views');

app.use(authRouter);

app.get('/', (req, res, next) => res.render('index'));

app.listen(3000, () => {
  console.log('Listening on port 3000');
});