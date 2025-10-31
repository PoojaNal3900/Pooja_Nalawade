const express = require("express");
require("dotenv").config();
const morgan = require("morgan");
const cors = require("cors");

const userRoutes = require("./src/routes/user-routes");
const eventRoutes = require("./src/routes/event-routes");
const employeeRoutes = require("./src/routes/employee-routes");

const PORT = process.env.PORT || 8080;

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(morgan("combined"));

app.use("/api/users", userRoutes);
app.use("/api/events", eventRoutes);
app.use("/api/employees", employeeRoutes);

app.listen(PORT, () =>
  console.log(`Students Events Service is running on PORT - ${PORT} !`)
);
