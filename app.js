const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const cors = require("cors");

//Initialize the app

const app = express();

//Middlewares
//Form Data Middleware
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);
//Json Body Middleware
app.use(bodyParser.json());
//Cors Middleware
app.use(cors());
//Setting up the static directory
app.use(express.static(path.join(__dirname, "public")));

//Bring in the Database Config and connect with the database
const db = require("./config/keys").mongoURI;
mongoose.connect(
  db,
  { useNewUrlParser: true, useUnifiedTopology: true },
  (err) => {
    if (err) {
      console.log(`Unable to connect with the database ${err}`);
    } else {
      console.log(`Database connected successfully ${db}`);
    }
  }
);

// app.get("/", (req, res) => {
//   return res.send("<h1>Hello World1</h1>");
// });

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});