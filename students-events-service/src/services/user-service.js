const { insertUser, checkUserIdentity } = require("../dal/user-dal");

class UserService {
  async registerUserCredentials(user) {
    try {
      return await insertUser(user);
    } catch (error) {
      throw error;
    }
  }
  async checkUserCredentials(user) {
    try {
      return await checkUserIdentity(user);
    } catch (error) {
      throw error;
    }
  }
}

module.exports = UserService;
