import { faker } from "@faker-js/faker";
import mongoose from "mongoose";
import dotenv from "dotenv";
import Product from "../models/Product.js";
import Category from "../models/Category.js";

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/proshop";

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("MongoDB Connected...");
  } catch (err) {
    console.error("DB Connection Error:", err.message);
    process.exit(1);
  }
};

const seedData = async () => {
  try {
    await Product.deleteMany();
    await Category.deleteMany();

    console.log("Old data cleared...");

    const categoryNames = [
      "Electronics",
      "Fashion",
      "Home & Kitchen",
      "Sports & Fitness",
      "Beauty & Health",
      "Books & Stationery",
      "Toys & Baby",
      "Groceries",
      "Automotive",
      "Jewellery",
    ];

    const categories = await Category.insertMany(
      categoryNames.map((name) => ({
        name,
        slug: name.toLowerCase().replace(/ & /g, "-").replace(/ /g, "-"),
        image: faker.image.urlPicsumPhotos({
          width: 640,
          height: 480,
          category: name.toLowerCase(),
        }),
      }))
    );

    console.log(`Categories seeded: ${categories.length}`);

    const products = [];

    for (const category of categories) {
      for (let i = 0; i < 20; i++) {
        const name = faker.commerce.productName();
        const price = parseFloat(
          faker.commerce.price({ min: 500, max: 10000 })
        );

        products.push({
          name,
          sku: faker.string.uuid(),
          description: faker.commerce.productDescription(),
          price,
          discount: faker.number.int({ min: 0, max: 30 }),
          categoryId: category._id,
          brand: faker.company.name(),
          images: [
            faker.image.urlPicsumPhotos({ width: 640, height: 480 }),
            faker.image.urlPicsumPhotos({ width: 640, height: 480 }),
          ],
          stock: faker.number.int({ min: 10, max: 100 }),
          rating: faker.number.float({ min: 3, max: 5, precision: 0.1 }),
          numReviews: faker.number.int({ min: 0, max: 100 }),
          attributes: {
            color: faker.color.human(),
            material: faker.commerce.productMaterial(),
            warranty: `${faker.number.int({ min: 6, max: 24 })} Months`,
          },
          isFeatured: faker.datatype.boolean(),
          createdAt: faker.date.past(),
          updatedAt: new Date(),
        });
      }
    }

    await Product.insertMany(products);

    console.log(`Products seeded: ${products.length}`);
    console.log("Database seeding completed successfully!");
    process.exit();
  } catch (err) {
    console.error("Seeding Error:", err);
    process.exit(1);
  }
};

await connectDB();
await seedData();
