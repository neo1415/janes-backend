
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Database configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// VULNERABILITY: Insecure CORS configuration
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // Allows any origin
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// VULNERABILITY: Insecure session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'insecure-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Serve static files
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// VULNERABILITY: Insecure file upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = req.body.path || 'uploads/';
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage: storage });

// Initialize database
async function initializeDatabase() {
  try {
    const client = await pool.connect();
    
    // Create tables
    await client.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(50) DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      price DECIMAL(10,2) NOT NULL,
      category VARCHAR(100),
      image VARCHAR(255),
      in_stock BOOLEAN DEFAULT true,
      admin_notes TEXT
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      total DECIMAL(10,2) NOT NULL,
      status VARCHAR(50) DEFAULT 'pending',
      customer_name VARCHAR(255),
      customer_email VARCHAR(255),
      customer_address TEXT,
      payment_info TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS reviews (
      id SERIAL PRIMARY KEY,
      product_id INTEGER,
      user_id INTEGER,
      rating INTEGER,
      comment TEXT,
      approved BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Insert default data if not exists
    const userCheck = await client.query('SELECT COUNT(*) FROM users');
    if (userCheck.rows[0].count === '0') {
      await client.query(`INSERT INTO users (username, email, password, role) VALUES 
        ('admin', 'admin@widgets.com', 'admin123', 'admin'),
        ('jane', 'jane@widgets.com', 'password123', 'admin'),
        ('demo', 'demo@widgets.com', 'demo', 'user')`);

      await client.query(`INSERT INTO products (name, description, price, category, image, in_stock, admin_notes) VALUES 
        ('Super Widget', 'Amazing widget with incredible features', 29.99, 'electronics', '/api/placeholder/300/200', true, 'High margin item'),
        ('Mega Widget', 'Professional grade widget for serious users', 49.99, 'electronics', '/api/placeholder/300/200', true, 'Best seller'),
        ('Ultra Widget', 'Premium widget with advanced capabilities', 79.99, 'electronics', '/api/placeholder/300/200', true, 'Luxury item'),
        ('Basic Widget', 'Simple widget for everyday use', 19.99, 'electronics', '/api/placeholder/300/200', false, 'Low cost option')`);
    }

    client.release();
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

// Authentication Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // VULNERABILITY: SQL Injection - Direct string interpolation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const result = await pool.query(query);
    
    if (result.rows.length > 0) {
      const user = result.rows[0];
      req.session.userId = user.id;
      req.session.role = user.role;
      
      res.json({
        success: true,
        user: { id: user.id, username: user.username, email: user.email, role: user.role },
        token: 'fake-jwt-token-' + user.id
      });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    // VULNERABILITY: Verbose error messages
    res.status(500).json({ 
      success: false, 
      message: 'Login failed', 
      error: error.message,
      stack: error.stack 
    });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // VULNERABILITY: No input validation, plaintext password storage
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, role',
      [username, email, password]
    );
    
    const user = result.rows[0];
    req.session.userId = user.id;
    req.session.role = user.role;
    
    res.json({
      success: true,
      user: user,
      token: 'fake-jwt-token-' + user.id
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed',
      error: error.message 
    });
  }
});

// Products Routes
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE in_stock = true');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/search', async (req, res) => {
  try {
    const { q } = req.query;
    
    // VULNERABILITY: SQL Injection in search
    const query = `SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;
    const result = await pool.query(query);
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      query: req.query.q,
      stack: error.stack 
    });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE id = $1', [req.params.id]);
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).json({ error: 'Product not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Orders Routes
app.post('/api/orders/checkout', async (req, res) => {
  try {
    const { items, total, customerInfo, paymentInfo } = req.body;
    
    // VULNERABILITY: Storing sensitive payment data
    const result = await pool.query(
      'INSERT INTO orders (user_id, total, customer_name, customer_email, customer_address, payment_info) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [req.session.userId || 0, total, customerInfo.name, customerInfo.email, customerInfo.address, JSON.stringify(paymentInfo)]
    );
    
    res.json({ success: true, order: result.rows[0] });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message,
      sensitiveData: req.body 
    });
  }
});

app.get('/api/orders', async (req, res) => {
  try {
    const userId = req.query.userId || req.session.userId;
    
    // VULNERABILITY: IDOR - No authorization check
    const result = await pool.query('SELECT * FROM orders WHERE user_id = $1', [userId]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin Routes
app.get('/api/admin/users', async (req, res) => {
  try {
    // VULNERABILITY: Weak admin check
    if (req.session.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const result = await pool.query('SELECT id, username, email, role, created_at FROM users');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY: Debug endpoint exposing sensitive information
app.get('/api/debug', (req, res) => {
  res.json({
    environment: process.env,
    session: req.session,
    headers: req.headers,
    database_url: process.env.DATABASE_URL,
    ftp_credentials: { username: 'jane', password: 'password123' }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Initialize and start server
initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('🚨 VULNERABLE SERVER RUNNING 🚨');
    console.log(`Port: ${PORT}`);
    console.log('Environment: Development (Insecure)');
    console.log('Database: PostgreSQL');
    console.log('⚠️  WARNING: This server contains intentional security vulnerabilities!');
    console.log('   Only use for educational purposes in isolated environments.');
    console.log('Default Accounts:');
    console.log('- admin:admin123 (Admin)');
    console.log('- jane:password123 (Admin)');
    console.log('- demo:demo (User)');
    console.log('FTP Credentials: jane:password123');
  });
});
