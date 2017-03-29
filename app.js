const express = require('express');
const bcrypt = require('bcryptjs');
const csrf = require('csurf');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const sessions = require('client-sessions');

const Schema = mongoose.Schema;

mongoose.connect('mongodb://localhost:27017/auth');
const ObjectId = Schema.ObjectId;

const User = mongoose.model('Users', new Schema({
  id: ObjectId,
  firstName: String,
  lastName: String,
  email: {
    type: String,
    unique: true,
  },
  password: String,
}));

const app = express();
app.set('view engine', 'jade');

// middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(sessions({
  cookieName: 'session',
  secret: 'sldfj23^%&^(*(84298ldfjks#$@lj',
  duration: 30 * 60 * 1000,
  activeDuration: 5 * 60 * 1000,
  httpOnly: true, // dont let browser javascript access cookies ever
  secure: true, // only use cookies over https
  ephemeral: true, // delete this cookie when the browser is closed
}));

app.use(csrf());

app.use(function (req, res, next) {
  if (req.session && req.session.user) {
    User.findOne({ email: req.session.user.email }, function (err, user) {
      if (user) {
        req.user = user;
        delete req.user.password;
        req.session.user = user;
        res.locals.user = user;
      }
      next();
    });
  } else {
    next();
  }
});

function requireLogin(req, res, next) {
  if (!req.user) {
    res.redirect('/login');
  } else {
    next();
  }
}

app.get('/', (req, res) => {
  res.render('index.jade');
});

app.get('/register', (req, res) => {
  res.render('register.jade', { csrfToken: req.csrfToken() });
});

app.post('/register', (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
  const user = new User({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: hash,
  });
  user.save((err) => {
    if (err) {
      let err = 'Something bad happened! Try again';
      if (err.code === 11000) {
        err = 'That email is already taken, try another';
      }

      res.render('register.jade', { error: err });
    } else {
      req.session.user = user;
      res.redirect('/dashboard');
    }
  });
});

app.get('/login', (req, res) => {
  res.render('login.jade', { csrfToken: req.csrfToken() });
});

app.post('/login', (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (!user) {
      res.render('login.jade', { error: 'Invalid email or password' });
    } else {
      if (bcrypt.compareSync(req.body.password, user.password)) {
        req.session.user = user;
        res.redirect('/dashboard');
      } else {
        res.render('login.jade', { error: 'Invalid email or password' });
      }
    }
  });
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard.jade');
});

app.get('/logout', (req, res) => {
  req.session.reset();
  res.redirect('/');
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
