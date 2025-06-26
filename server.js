const express = require('express');
const path = require('path');
require('dotenv').config();
const cookieParser = require('cookie-parser');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session); // 🔑 Added
const db = require('./config/db'); // 🔑 PostgreSQL DB connection
const { createUserTable } = require('./models/userModel');
const { createFoodTable } = require('./models/foodModel');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ✅ Secure session store using PostgreSQL
app.use(session({
  store: new pgSession({
    pgPromise: db,
  }),
  secret: process.env.SESSION_SECRET || 'secretkey',
  resave: false,
  saveUninitialized: false,
}));

// Set EJS view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Route imports
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const userRoute = require('./routes/userRoute');

app.use('/', authRoutes);
app.use('/admin', adminRoutes);
app.use('/user', userRoute);

// Create tables
createUserTable();
createFoodTable();

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
