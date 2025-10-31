const {
  fetchAllEvents,
  fetchEventDetails,
  insertEvent,
} = require("../dal/event-dal");

class EventService {
  async getAllEvents() {
    try {
      return await fetchAllEvents();
    } catch (error) {
      throw error;
    }
  }
  async getEventDetails(eventId) {
    try {
      return await fetchEventDetails(eventId);
    } catch (error) {
      throw error;
    }
  }
  async registerEvent(event) {
    try {
      return await insertEvent(event);
    } catch (error) {
      throw error;
    }
  }
}

//Singleton Pattern
module.exports = new EventService();
