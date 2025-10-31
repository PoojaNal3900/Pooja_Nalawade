const express = require("express");

const employeeServiceObj = require("../services/employee-service");

const {
  authorizationMiddleware,
} = require("../middleware/authorization-middleware");

const employeeRoutes = express.Router();
//employeeRoutes.use(authorizationMiddleware);
//Declare Children routes
//Default Child Route - http://localhost:9090/api/employees
employeeRoutes.get("/", async (request, response) => {
  try {
    const employees = await employeeServiceObj.getAllEmployees();
    if (employees.length > 0) {
      response.status(200).json(employees);
    } else {
      response.status(404).json({
        message:
          "We didn't find any employees record! Please try after some time!",
        success: false,
      });
    }
  } catch (error) {
    response.status(400).json(error);
  }
});

//Post Endpoint Address/Route - http://localhost:9090/api/employees
employeeRoutes.post("/", async (request, response) => {
  try {
    let acknowledgement = await employeeServiceObj.registerEmployee(
      request.body
    );
    console.log(acknowledgement);
    if (acknowledgement.acknowledged === true) {
      response.status(201).json(acknowledgement);
    } else {
      response.status(400).json({
        message: "Employee Registration Failed! Please try one more time1",
        success: false,
      });
    }
  } catch (error) {
    response.status(400).json(error);
  }
});

//Parameterized Route - http://localhost:9090/api/employees/2072
employeeRoutes.get("/:employeeId", async (request, response) => {
  try {
    const employee = await employeeServiceObj.getEmployeeDetails(
      Number.parseInt(request.params.employeeId)
    );
    if (employee) {
      response.status(200).json(employee);
    } else {
      response.status(404).json({
        message: `We didn't find any employee with the Id ${request.params.employeeId}!`,
        success: false,
      });
    }
  } catch (error) {
    response.status(400).json(error);
  }
});
module.exports = employeeRoutes;
