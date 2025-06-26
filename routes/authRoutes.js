const express = require('express');
const authController = require('../controllers/authController');    
const router = express.Router();

// Root route
router.get('/', (req, res) => {
    res.render('pages/landing');
});

// Signup routes
router.get('/signup', authController.getSignUpPage);
router.post('/signup', authController.postSignUp);

// Email verification
router.get('/verify-email', authController.verifyEmail);

// Login routes
router.get('/login', authController.getLoginPage);  
router.post('/login', authController.postLogin);

// forgot password routes
router.get('/forgot-password', authController.getForgotPassword);
router.post('/forgot-password', authController.postForgotPassword);
router.get('/reset-password', authController.getResetPassword);
router.post('/reset-password', authController.resetPassword);

//logout route
router.get('/logout', authController.logout);


module.exports = router;
