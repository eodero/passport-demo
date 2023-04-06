require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const MongoDBStore = require('connect-mongodb-session')(session);

let store = new MongoDBStore({
  uri: process.env.MONGO_URI,
  collection: 'sessions'
});

// Catch errors
store.on('error', function (error) {
  console.log(error);
});


const Schema = mongoose.Schema;

const mongoDB = process.env.MONGO_URI;
mongoose.connect(mongoDB, {
    useUnifiedTopology: true,
    useNewUrlParser: true,
    })
const db = mongoose.connection;
    db.on("error", console.error.bind(console, 'mongo connection error'));

const User = mongoose.model('User', new Schema({
    username: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    }
}))

const app = express();
///-option 1
// app.set('views', __dirname + '/views');
///-option 2
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true, store }));

//1) - setting up the LocalStrategy
passport.use(
    new LocalStrategy(async(username, password, done) => {
        try {
            const user = await User.findOne({ username });
            if(!user){
                return done(null, false, {
                    message: 'Incorrect username',
                })
            };
            if(user.password !== password){
                return done(null, false, {
                    message: 'Incorrect password',
                })
            };
            return done(null, user);
        } catch (err){
            return done(err)
        }
  })
  );
  
  //2) - sessions and serialization
  //-extract a unique identifier for the user (such as their ID) and store it in the cookie.
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  //-allows the application to retrieve and use user data throughout the session
  passport.deserializeUser(async function(id, done) {
    try{
        const user = await User.findById(id);
        done(null, user)
    } catch (err){
        done(err);
    }
  })

app.use(passport.initialize());
app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
const authMiddleware = (req, res, next) => {
    if (!req.user) {
      if (!req.session.messages) {
        req.session.messages = [];
      }
      req.session.messages.push("You can't access that page before logon.");
      res.redirect('/');
    } else {
      next();
    }
  }
  
app.get("/", (req, res) => {
    let messages = [];
    if(req.session.messages) {
        messages = req.session.messages;
        req.session.messages = [];
    }
    res.render("index", {
        user: req.user? req.user: null,
        messages
    })
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
    try{
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
          username: req.body.username,
          password: hashedPassword
        });
     await user.save();
    res.redirect("/");
        
    } catch (err) {
        return next(err)
    }
})

app.post("/log-in", passport.authenticate("local", {
      successRedirect: "/",
      failureRedirect: "/"
    })
  );
  app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.get('/restricted', authMiddleware, (req, res) => {
    if (!req.session.pageCount) {
      req.session.pageCount = 1;
    } else {
      req.session.pageCount++;
    }
    res.render('restricted', { pageCount: req.session.pageCount });
  })


app.listen(3000, () => console.log("app listening on port 3000!"));