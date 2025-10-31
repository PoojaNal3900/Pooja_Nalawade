const {
  fetchAllEmployees,
  fetchEmployeeDetails,
  insertEmployee,
} = require("../dal/employee-dal");

class EmployeeService {
  async getAllEmployees() {
    try {
      return await fetchAllEmployees();
    } catch (error) {
      throw error;
    }
  }
  async getEmployeeDetails(employeeId) {
    try {
      return await fetchEmployeeDetails(employeeId);
    } catch (error) {
      throw error;
    }
  }
  async registerEmployee(employee) {
    try {
      return await insertEmployee(employee);
    } catch (error) {
      throw error;
    }
  }
}

//Singleton Pattern
module.exports = new EmployeeService();
