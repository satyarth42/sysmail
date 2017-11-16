var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var flash = require('connect-flash');
var index = require('./routes/index');
var users = require('./routes/users');
var mongoose = require('mongoose');
var passport = require('passport');
var socket_io = require('socket.io');
var expressSession = require('express-session');
var mails = require('./models/mails');
var app = express();
var io = socket_io();
app.io = io;
mongoose.connect('mongodb://127.0.0.1:27017/mailsys');
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(flash());
app.use(expressSession({
    secret: 'hY797S2APCzSkjhgndFbsngMSd7dy',
    resave: true,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/', index);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

var onlineUsers = {};
io.on('connection',function(socket){
    socket.on('new_user',function(data){
        onlineUsers[data.email]=socket['id'];
    });
    socket.on('new_mail',function(data){
        socket.to(onlineUsers[data.receiver]).emit('new_mail', data);
        var mail = new mails({
            "sender":data.sender,
            "receiver":data.receiver,
            "subject":data.subject,
            "content":data.content,
            "date":data.date
        });
        mail.save(function (err, updated) {
            if (err) console.log(err);
        });
    });
});

module.exports = app;
