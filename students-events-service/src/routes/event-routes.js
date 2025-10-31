const express = require("express");

const eventServiceObject = require("../services/event-service");

const {
  authorizationMiddleware,
} = require("../middleware/authorization-middleware");

const eventRoutes = express.Router();
eventRoutes.use(authorizationMiddleware);
//Declare Children routes
//Default Child Route - http://localhost:9090/api/events
eventRoutes.get("/", async (request, response) => {
  try {
    const events = await eventServiceObject.getAllEvents();
    if (events.length > 0) {
      response.status(200).json(events);
    } else {
      response.status(404).json({
        message:
          "We didn't find any events! Please try after some time!",
        success: false,
      });
    }
  } catch (error) {
    response.status(400).json(error);
  }
});

//Post Endpoint Address/Route - http://localhost:9090/api/events
eventRoutes.post("/", async (request, response) => {
  try {
    console.log(request.body)
    let acknowledgement = await eventServiceObject.registerEvent(
      request.body
    );
    console.log(acknowledgement);
    if (acknowledgement.acknowledged === true) {
      response.status(201).json(acknowledgement);
    } else {
      response.status(400).json({
        message: "Event Registration Failed! Please try one more time!",
        success: false,
      });
    }
  } catch (error) {
    response.status(400).json(error);
  }
});

//Parameterized Route - http://localhost:9090/api/events/2072
eventRoutes.get("/:eventId", async (request, response) => {
  try {
    const event = await eventServiceObject.getEventDetails(
      Number.parseInt(request.params.eventId)
    );
    if (event) {
      response.status(200).json(event);
    } else {
      response.status(404).json({
        message: `We didn't find any event with the Id ${request.params.eventId}!`,
        success: false,
      });
    }
  } catch (error) {
    response.status(400).json(error);
  }
});
module.exports = eventRoutes;
