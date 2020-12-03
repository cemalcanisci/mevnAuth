const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const password = require("passport");
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
});

module.exports = router;
