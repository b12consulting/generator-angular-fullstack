'use strict';

var User = require('./user.model');
var passport = require('passport');
var config = require('../../config/environment');
var jwt = require('jsonwebtoken');

var validationError = function(res, err) {
    return res.json(422, err);
};

/**
 * Get list of users
 * restriction: 'admin'
 */
exports.index = function(req, res, next) {
    User.findQ({}, '-salt -hashedPassword')
        .then(function(users) {
            res.json(200, users);
        })
        .catch(next)
        .done();
};

/**
 * Creates a new user
 */
exports.create = function(req, res, next) {
    var newUser = new User(req.body);
    newUser.provider = 'local';
    newUser.role = 'user';
    newUser.saveQ()
        .then(function(user) {
            var token = jwt.sign({
                _id: user._id
            }, config.secrets.session, {
                expiresInMinutes: 60 * 5
            });

            res.json({
                token: token
            });
        })
        .catch(next)
        .done();
};

/**
 * Get a single user
 */
exports.show = function(req, res, next) {
    var userId = req.params.id;

    User.findByIdQ(userId)
        .then(function(user) {
            if (!user) return res.send(401);
            res.json(user.profile);
        })
        .catch(next)
        .done();
};

/**
 * Deletes a user
 * restriction: 'admin'
 */
exports.destroy = function(req, res, next) {
    User.findByIdAndRemoveQ(req.params.id)
        .then(function(user) {
            return res.send(204);
        })
        .catch(next)
        .done;
};

/**
 * Change a users password
 */
exports.changePassword = function(req, res, next) {
    var userId = req.user._id;
    var oldPass = String(req.body.oldPassword);
    var newPass = String(req.body.newPassword);

    User.findByIdQ(userId)
        .then(function(user) {
            if (!user.authenticate(oldPass)) {
                throw new Error(403);
            }

            user.password = newPass;
            return user.saveQ();
        })
        .then(function() {
            res.send(200);
        })
        .catch(next)
        .done();
};

/**
 * Get my info
 */
exports.me = function(req, res, next) {
    var userId = req.user._id;
    User.findOneQ({
                _id: userId
            },
            '-salt -hashedPassword')
        .then(function(user) { // don't ever give out the password or salt
            if (!user) throw new Error(401);
            res.json(user);
        })
        .catch(next)
        .done();
};

/**
 * Authentication callback
 */
exports.authCallback = function(req, res, next) {
    res.redirect('/');
};