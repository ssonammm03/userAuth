const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');


router.get('/dashboard', adminController.getAdminDashboard);


router.get('/add-food', adminController.getAddFood);
router.post('/add-food', adminController.postAddFood);


router.get('/food', adminController.getAllFood);


router.get('/edit-food/:id', adminController.getEditFood);
router.post('/edit-food/:id', adminController.postEditedFood);
router.post('/delete-food/:id', adminController.deleteFood);




module.exports = router;
