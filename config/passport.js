const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt= require('bcryptjs');


//local user model
const User=require('../models/User');
const passport = require('passport');
const facebookStrategy = require('passport-facebook');
const { response } = require('express');



//in case of login
module.exports = (function(passport){
    passport.use(
        new LocalStrategy({ usernameField: 'email'},(email,password,done)=>{
            //match user
            User.findOne({email:email})
            .then(user =>{
                if(!user){
                    return done(null,false,{message: 'This email is not registered'});
                }
                //match password
                bcrypt.compare(password, user.password, (err, isMatch)=>{
                    if(err) throw err;
                    if(isMatch){
                        return done(null,user);
                    }
                    else{
                        return done(null, false, {message: 'Password incorrect'});
                    }
                })
            })
            .catch(err=>console.log(err))
        })
    );
    passport.use(new facebookStrategy({

        // pull in our app id and secret from our auth.js file
        clientID        : "507406130129064",
        clientSecret    : "77b5859c051c4d97dd99b6e167fadb63",
        callbackURL     : "http://localhost:5000/facebook/callback",
        profileFields: ['id', 'displayName', 'name','email']
    
    },// facebook will send back the token and profile
    function(token, refreshToken, profile, done) {
    
        process.nextTick(function() {

            // find the user in the database based on their facebook id
            User.findOne({ 'email' : profile.emails[0].value }, function(err, user) {
    
                // if there is an error, stop everything and return that
                // ie an error connecting to the database
                if (err)
                    return done(err);
    
                // if the user is found, then log them in
                if (user) {
                    console.log("user found")
                    console.log(user)
                    return done(null, user); // user found, return that user
                } else {
                    // if there is no user found with that facebook id, create them
                    var newUser            = new User();
    
                    // set all of the facebook information in our user model
                    newUser.uid    = profile.id; // set the users facebook id                   
                                     
                    newUser.name  = profile.displayName; // look at the passport user profile to see how names are returned
                    newUser.email = profile.emails[0].value; // facebook can return multiple emails so we'll take the first
                    newUser.password = 'qwerty';
                    console.log(profile);
                    
                    // save our user to the database
                    newUser.save(function(err) {
                        if (err)
                            throw err;
    
                        // if successful, return the new user
                        return done(null, newUser);
                    });
                }
    
            });
        })
    }));

  


    passport.serializeUser((user,done)=>{
        done(null,user.id);
    });


    passport.deserializeUser((id,done)=>{
        User.findById(id,(err,user)=>{
            done(err,user);
        });
    });

})