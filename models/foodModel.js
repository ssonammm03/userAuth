const db = require('../config/db');


const createFoodTable = async () => {
  try {
    await db.none(`
      CREATE TABLE IF NOT EXISTS food_items (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        image_url TEXT,
        price NUMERIC(10, 2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("✅ Food table ensured.");
  } catch (err) {
    console.error("❌ Error creating food table:", err);
  }
};




module.exports = {
  createFoodTable
};


