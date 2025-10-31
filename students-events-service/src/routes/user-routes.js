const express = require("express");
const {
  verifyRefreshToken,
  generateAccessToken,
} = require("../utility-functions");
const UserService = require("../services/user-service");

const userRoutes = express.Router();

//Child Post Route - http://localhost:9090/api/users
userRoutes.post("/", async (request, response) => {
  try {
    const userService = new UserService();
    let acknowledgement = await userService.registerUserCredentials(
      request.body
    );
    if (acknowledgement.acknowledged === true) {
      response.status(201).json(acknowledgement);
    } else {
      response.status(400).json({
        message: "User Registration Failed! Please try one more time!",
        success: false,
      });
    }
  } catch (error) {
    response.status(400).json(error);
  }
});
//Child Post Route - http://localhost:9090/api/users/authenticate
userRoutes.post("/authenticate", async (request, response) => {
  try {
    const userService = new UserService();
    let acknowledgement = await userService.checkUserCredentials(request.body);
    if (acknowledgement.success === true) {
      response.status(200).json(acknowledgement);
    } else {
      response.status(200).json(acknowledgement);
    }
  } catch (error) {
    response.status(400).json(error);
  }
});
userRoutes.post("/refresh", async (request, response) => {
  try {
    const refreshToken = request.body.refreshToken;
    const userInfo = await verifyRefreshToken(refreshToken);
    const newToken = await generateAccessToken(userInfo.email, userInfo.role);
    response.status(200).json(newToken);
  } catch (error) {
    response.status(400).json(error);
  }
});
module.exports = userRoutes;
