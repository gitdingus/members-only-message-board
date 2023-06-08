const User = require('../models/user.js');

function configPassportLocalStrategy(passport, LocalStrategy) {
  passport.use(new LocalStrategy(
    async function (username, password, done) {
      try {
        const user = await User.findOne({ username: username }, 'salt hash').exec();
        
        if (user === null) {
          return done(null, false);
        }
  
        if (validPassword(password, user.salt, user.hash) === false) {
          return done(null, false);
        }
  
        return done(null, user);
      } catch (err) {
        done(err);
      }  
    }
  ));
  
  passport.serializeUser(function (user, cb) {
    return cb(null, user._id);
  });
  
  passport.deserializeUser(async function (id, cb) {
    try {
      const user = await User.findById(id);
  
      if (user === null) {
        throw new Error('Error deserializing user: User not found');
      } else {
        cb(null, user);
      }
    } catch (err) {
      cb(err);
    } 
  });
}

module.exports = configPassportLocalStrategy;