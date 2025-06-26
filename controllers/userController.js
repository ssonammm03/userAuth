const db = require('../config/db');

exports.getDashboard = async (req, res) => {
    res.render('user/dashboard', { message: null });
};

exports.getAllFood = async (req, res) => {
    try {
        const foods = await db.any('SELECT * FROM food_items ORDER BY created_at DESC');
        res.render('user/food', { foods });
    } catch (error) {
        console.error('Error fetching food items:', error);
        res.status(500).send('Internal Server Error');
    }
};