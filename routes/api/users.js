const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const key = require("../../config/keys").secret;
const User = require("../../models/User");

/**
 *@route POST api/users/register
 *@desc Register the User
 *@access Public
 */
router.post("/register", (req, res) => {
  let { name, username, email, password, confirm_password } = req.body;
  if (password !== confirm_password) {
    return res.status(400).json({
      msg: "Password do not match",
    });
  }
  //Check for the unique Username
  User.findOne({ username }).then((user) => {
    if (user) {
      return res.status(400).json({
        msg: "Username is already taken",
      });
    }
  });
  //Check for the unique email
  User.findOne({
    email,
  }).then((user) => {
    if (user) {
      return res.status(400).json({
        msg: "Email is already registred. Did you forgot your password.",
      });
    }
  });
  //The data is valid and now we can register the user
  let newUser = new User({
    name,
    username,
    password,
    email,
  });
  //Hash the password
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(newUser.password, salt, (err, hash) => {
      if (err) throw new Error(err);
      newUser.password = hash;
      newUser.save().then((user) => {
        return res.status(200).json({
          success: true,
          msg: "Hurry! User is now registered.",
        });
      });
    });
  });
});

/**
 * @route POST api/users/login
 * @desc Signing in the User
 * @access Public
 */
router.post("/login", (req, res) => {
  let { username, password } = req?.body;
  User.findOne({
    username,
  }).then((user) => {
    if (!user) {
      return res.status(404).json({
        msg: "Username is not found",
        success: false,
      });
    }
    //If there is user we are now going to compare the password
    bcrypt.compare(password, user.password).then((isMatch) => {
      if (isMatch) {
        //User's password is correct and we need to send the JSON token for that user
        const { _id, name, email } = user;
        const payload = {
          _id,
          username: user.username,
          name,
          email,
        };
        jwt.sign(payload, key, { expiresIn: 604800 }, (err, token) => {
          res.status(200).json({
            success: true,
            token: `Bearer ${token}`,
            msg: "Hurry! You are now logged in",
          });
        });
      } else {
        return res.status(404).json({
          msg: "Incorrect password.",
          success: false,
        });
      }
    });
  });
});

/**
 * @route GET api/users/profile
 * @desc Return the User's Data
 * @access Private
 */
router.get(
  "/profile",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    return res.status(200).json({
      user: req.user,
    });
  }
);
module.exports = router;
