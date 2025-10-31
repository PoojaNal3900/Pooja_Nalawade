const { MongoClient } = require("mongodb");

const client = new MongoClient(process.env.MONGODB_SERVER);

async function fetchAllEmployees() {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const employeesCollection = db.collection("employees");
    const documents = employeesCollection.find();
    return await documents.toArray();
  } catch (error) {
    throw error;
  }
}
async function fetchEmployeeDetails(employeeId) {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const employeesCollection = db.collection("employees");
    const document = employeesCollection.findOne({ employeeId: employeeId });
    return await document;
  } catch (error) {
    throw error;
  }
}
async function insertEmployee(employee) {
  try {
    let newEmployee = {
      ...employee,
      employeeId: Number.parseInt(employee.employeeId),
      zipcode: Number.parseInt(employee.zipcode),
      joiningDate: new Date(employee.joiningDate),
      avatar: "images/noimage.png",
    };
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const employeesCollection = db.collection("employees");
    const result = employeesCollection.insertOne(newEmployee);
    return await result;
  } catch (error) {
    throw error;
  }
}

module.exports = {
  fetchAllEmployees,
  fetchEmployeeDetails,
  insertEmployee,
};
