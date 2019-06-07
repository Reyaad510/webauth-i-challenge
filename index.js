const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');


const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();
const sessionConfig = {
  name: 'Joker',
  secret: 'secret string',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production' ? true : false,
    httpOnly: true
  }
}

server.use(session(sessionConfig));
server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("Is this thing working?");
});

// Register
server.post('/api/register', (req, res) => {
    let user = req.body;
  
    if (!user.username || !user.password) {
      return res.status(500).json({ message: "Need name and pass" })
    }
  
    if (user.password.length < 6) {
      return res.status(400).json({ message: 'Pass too short!' })
    }
  
    const hash = bcrypt.hashSync(user.password, 14);
    user.password = hash;
  
    Users.add(user)
      .then(saved => {
        res.status(201).json(saved);
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });
  
  
  // LOGIN
  server.post('/api/login', (req, res) => {
    let { username, password } = req.body;
  
  
    Users.findBy({ username })
      .first()
      .then(user => {
        if(!username || !password) {
          return res.status(401).json({ message: 'Invalid Credentials' })
        }
  
        if (user && bcrypt.compareSync(password, user.password)) {
          res.status(200).json({ message: `Welcome ${user.username}!` });
        } else {
          res.status(401).json({ message: 'You shall not pass!' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });
  
  
  // MIDDLE WARE
  function authorize(req, res, next) {
    const username = req.headers['x-username'];
    const password = req.headers['x-password'];
  
    Users.findBy({ username })
      .first()
      .then(user => {
  
        if(!username || !password) {
          return res.status(401).json({ message: 'Invalid Credentials' })
        }
  
        if (user && bcrypt.compareSync(password, user.password)) {
          next()
        } else {
          res.status(401).json({ message: 'You shall not pass!' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  }
  

  // USERS

  server.get('/api/users', authorize, (req, res) => {
    Users.find()
      .then(users => {
        res.json(users);
      })
      .catch(err => res.send(err));
  });





const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));