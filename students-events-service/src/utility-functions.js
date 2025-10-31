const jwt = require("jsonwebtoken");

function generateAccessToken(email, role) {
  return new Promise((resolve, reject) => {
    let token = jwt.sign({ email, role }, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: "30m",
    });
    resolve({
      email,
      role,
      token,
    });
  });
}
function generateRefreshToken(email, role) {
  return new Promise((resolve, reject) => {
    let token = jwt.sign({ email, role }, process.env.REFRESH_TOKEN_SECRET, {
      expiresIn: "1m",
    });
    resolve({
      token,
    });
  });
}
function verifyAccessToken(accessToken) {
  return new Promise((resolve, reject) => {
    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, decode) => {
      if (err) reject(err);
      resolve({ email: decode.email, role: decode.role });
    });
  });
}
function verifyRefreshToken(refreshToken) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      (err, decode) => {
        if (err) reject(err);
        resolve({ email: decode.email, role: decode.role });
      }
    );
  });
}
module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
};
