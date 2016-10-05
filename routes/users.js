var express = require('express');
var router = express.Router();

//Passport y Localstrategy
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

//Lamando al modelo Usuario
var User = require('../models/user');

// Get Homepage
router.get('/register', function(req, res){
	res.render('register');
});

//Login
router.get('/login', function(req, res){
	res.render('login');
});

//index
//router.get('/index', function(req, res) {
//    res.render('index', { username: req.user.username });
//});

// Register user Post
router.post('/register', function(req, res){
	var name = req.body.name;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var passwor2 = req.body.password2;

	//console.log(name);
	//validation
	req.checkBody('name', 'El Nombre es Requerido').notEmpty();
	req.checkBody('email', 'El Email es Requerido').notEmpty();
	req.checkBody('email', 'Email no valido').isEmail();
	req.checkBody('username', 'Nombre de Usuario requerido').notEmpty();
	req.checkBody('password', 'El Password es Requerido').notEmpty();
	req.checkBody('password2', 'Confirma tu password').notEmpty();
	req.checkBody('password2', 'Password no coincide').equals(req.body.password);
	var errors = req.validationErrors();

	if(errors){
		//console.log('YES')
		res.render('register',{
			errors:errors
		});

	}else{
		//console.log('PASSED')
		//Si pasa la validacion
		var newUser = new User({
			name: name,
			email: email,
			username: username,
			password: password
		});
		User.createUser(newUser, function(err, user){
			if(err) throw err;
				console.log(user);
		});
		req.flash('success_msg','Se registro el usuario Correctamente.');
		res.redirect('/users/login');
	}
});

passport.use(new LocalStrategy(
  function(username, password, done) {
		User.getUserByUsername(username, function(err, user){
			if(err) throw err;
			if(!user){
				return done(null, false,{message: 'Unknown user'});
			}
			User.comparePassword(password, user.password, function(err, isMatch){
				if(err) throw err;
				if(isMatch){
					return done(null, user);
				}else{
					return done(null, false,{message: 'Password incorrecto'});
				}

			});
		});

  }));

//serializar passport
passport.serializeUser(function(user,done){
	done(null, user.id);

});

passport.deserializeUser(function(id, done){
	User.getuserById(id, function(err, user){
		done(err, user);
	});
});



router.post('/login',
  passport.authenticate('local',{successRedirect: '/', failureRedirect:'/users/login', failureFlash: true}),
  function(req, res) {
		res.redirect('/');

  });

	router.get('/logout', function(req, res){
		req.logout();
		req.flash('success_msg', 'Saliste de session correctamente :)');
		res.redirect('/users/login');

	});

module.exports = router;
