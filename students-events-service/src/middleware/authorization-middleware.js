const jwt = require("jsonwebtoken");
const { verifyAccessToken } = require("../utility-functions");

async function authorizationMiddleware(request, response, next) {
  let token =
    request.headers["bajaj-authorization-token"] ||
    request.body.token ||
    request.query.token;
    console.log(token);
  if (token) {
    try {
      const output = await verifyAccessToken(token);
      console.log(output)
      next();
    } catch (error) {
      response.status(401).json({
        message:
          "Your token is expired! Please re-login the re-generate the token!",
      });
      return;
    }
  } else {
    response.status(401).json({
      message: "You are missing the token! Please login to receive the token!",
    });
  }
}

module.exports = {
  authorizationMiddleware,
};
