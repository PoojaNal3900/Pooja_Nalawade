const { MongoClient } = require("mongodb");

const client = new MongoClient(process.env.MONGODB_SERVER);

async function fetchAllEvents() {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const eventsCollection = db.collection("events");
    const documents = eventsCollection.find();
    return await documents.toArray();
  } catch (error) {
    throw error;
  }
}
async function fetchEventDetails(eventId) {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const eventsCollection = db.collection("events");
    const document = eventsCollection.findOne({ eventId: eventId });
    return await document;
  } catch (error) {
    throw error;
  }
}
async function insertEvent(event) {
  try {
    let newEvent = {
      ...event,
      eventId: Number.parseInt(event.eventId),
      fees: Number.parseInt(event.fees),
      seatsFilled: Number.parseInt(event.seatsFilled),
      startDate: new Date(event.startDate),
      endDate: new Date(event.endDate),
      logo: "images/noimage.png",
    };
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const employeesCollection = db.collection("events");
    const result = employeesCollection.insertOne(newEvent);
    return await result;
  } catch (error) {
    throw error;
  }
}

module.exports = {
  fetchAllEvents,
  fetchEventDetails,
  insertEvent
};
