
const express=require('express');
const app=express();
const expressLayouts=require('express-ejs-layouts');
const mongoose=require('mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');
const facebookStrategy = require('passport-facebook');



//DB CONFIG
const db= require('./config/keys').MongoURI;
//Connect to mongo
mongoose.connect(db,{useNewUrlParser: true, useUnifiedTopology: true })
.then(()=>console.log("Mongodb is connected successfully!"))
.catch(err=>console.log(err)); 


//EJS
app.use(expressLayouts);
app.set('view engine','ejs');

//BodyParser
app.use(express.urlencoded({extended: false}));




//express session middleware
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true,
}))

//resert middleware
app.use(session({ secret: 'session secret key' }));

//passport middleware
app.use(passport.initialize());
app.use(passport.session());
//passport config
require('./config/passport')(passport);





app.get('/auth/facebook', passport.authenticate('facebook', { scope : ['email']}));
app.get('/facebook/callback',
		passport.authenticate('facebook', {
			successRedirect : '/dashboard',
			failureRedirect : '/'
        }));




//Connect Flash
app.use(flash());


//Global variables
app.use((req,res,next)=>{
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
})


//Routes
app.use('/',require('./routes/index'));
app.use('/users',require('./routes/users'));

const PORT=process.env.PORT || 5000
app.listen(PORT,console.log(`Server started at port ${PORT} `));