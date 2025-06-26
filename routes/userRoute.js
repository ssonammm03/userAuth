const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.get('/dashboard', userController.getDashboard);
router.get('/foods', userController.getAllFood); // Changed '/food' to '/foods'

module.exports = router;    
