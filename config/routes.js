"use strict";

const express = require("express");
const router = new express.Router();

const auth = require("../middleware/authentication");
const errorHandler = require("../middleware/errorHandler");

const itemCtrl = require("../controllers/item");
const userCtrl = require("../controllers/user");

const authTest = (req, res) => {
  res.json({
    message: "You've successfully authenticated.",
  });
};

router.get("/auth", auth.authenticate, authTest);

router.post("/login", userCtrl.loginUser);
router.post("/user", userCtrl.saveOne);

// router.use("", auth.authenticate);

// Routes for all users

router.get("/item", itemCtrl.findAll);
router.put("/item/:id", itemCtrl.updateOne);
router.post("/item", itemCtrl.saveOne);
// router.delete("/item/:id", itemCtrl.deleteOne);

router.put("/user/:id", userCtrl.updateOne);

// Routes accessisable only for admin

// router.use("", auth.onlyAdmin);

router.get("/user", userCtrl.findAll);
router.delete("/user/:id", userCtrl.deleteOne);

router.use("", errorHandler.handleErrors);

module.exports = router;
