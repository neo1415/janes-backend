const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

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
  secret: 'insecure-secret-key', // Hardcoded secret
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false, // Not secure over HTTP
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// VULNERABILITY: Insecure file upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // VULNERABILITY: No path validation - allows directory traversal
    const uploadPath = req.body.path || 'uploads/';
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // VULNERABILITY: Uses original filename without sanitization
    cb(null, file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  // VULNERABILITY: No file type or size restrictions
});

// Initialize database
const db = new sqlite3.Database('./database/widgets.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

function initializeDatabase() {
  // Create tables
  db.serialize(() => {
    // Users table - VULNERABILITY: Passwords stored in plaintext
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Products table
    db.run(`CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      category TEXT,
      image TEXT,
      in_stock BOOLEAN DEFAULT 1,
      admin_notes TEXT
    )`);

    // Orders table
    db.run(`CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      total REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      customer_info TEXT,
      payment_info TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Reviews table - VULNERABILITY: No XSS protection
    db.run(`CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER,
      user_id INTEGER,
      review_text TEXT,
      rating INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (product_id) REFERENCES products (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Insert default data
    insertDefaultData();
  });
}

function insertDefaultData() {
  // Default users - VULNERABILITY: Plaintext passwords
  const defaultUsers = [
    { username: 'admin', email: 'admin@widgets.com', password: 'admin123', role: 'admin' },
    { username: 'jane', email: 'jane@widgets.com', password: 'password123', role: 'admin' },
    { username: 'demo', email: 'demo@test.com', password: 'demo', role: 'user' }
  ];

  defaultUsers.forEach(user => {
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`,
      [user.username, user.email, user.password, user.role]);
  });

  // Default products
  const defaultProducts = [
    { name: 'Classic Red Widget', description: 'A beautiful handcrafted red widget perfect for any occasion.', price: 29.99, category: 'Classic', image: '/placeholder.svg', admin_notes: 'High profit margin item' },
    { name: 'Professional Blue Widget', description: 'The professional choice for serious widget enthusiasts.', price: 49.99, category: 'Professional', image: '/placeholder.svg', admin_notes: 'Customer favorite' },
    { name: 'Deluxe Gold Widget', description: 'Our premium gold widget with luxury finish.', price: 89.99, category: 'Deluxe', image: '/placeholder.svg', admin_notes: 'Markup: 300%' },
    { name: 'Eco-Friendly Green Widget', description: 'Sustainably made widget from recycled materials.', price: 34.99, category: 'Eco', image: '/placeholder.svg', admin_notes: 'Good for PR' },
    { name: 'Compact Mini Widget', description: 'Small but mighty! Our compact widget packs all the features.', price: 19.99, category: 'Mini', image: '/placeholder.svg', admin_notes: 'Cheapest to produce' },
    { name: 'Industrial Black Widget', description: 'Heavy-duty widget designed for industrial applications.', price: 119.99, category: 'Industrial', image: '/placeholder.svg', admin_notes: 'Government contract item' }
  ];

  defaultProducts.forEach(product => {
    db.run(`INSERT OR IGNORE INTO products (name, description, price, category, image, admin_notes) VALUES (?, ?, ?, ?, ?, ?)`,
      [product.name, product.description, product.price, product.category, product.image, product.admin_notes]);
  });
}

// Routes

// VULNERABILITY: SQL Injection in authentication
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  try {
    // VULNERABILITY: Direct string concatenation allows SQL injection
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    console.log('Executing query:', query); // VULNERABILITY: Logging sensitive queries
    
    db.get(query, (err, user) => {
      if (err) {
        // VULNERABILITY: Exposing detailed error messages
        return res.status(500).json({ 
          error: 'Database error', 
          details: err.message,
          query: query // Exposing query in error
        });
      }
      
      if (user) {
        req.session.userId = user.id;
        req.session.userRole = user.role;
        res.json({ 
          success: true, 
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
          }
        });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    });
  } catch (error) {
    // VULNERABILITY: Exposing stack traces
    res.status(500).json({ 
      error: 'Server error', 
      stack: error.stack 
    });
  }
});

// Register endpoint
app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;
  
  // VULNERABILITY: No input validation
  // VULNERABILITY: Storing plaintext passwords
  db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
    [username, email, password], function(err) {
      if (err) {
        return res.status(400).json({ 
          error: 'Registration failed', 
          details: err.message 
        });
      }
      
      req.session.userId = this.lastID;
      req.session.userRole = 'user';
      
      res.json({ 
        success: true, 
        user: { id: this.lastID, username, email, role: 'user' }
      });
    });
});

// Get products
app.get('/api/products', (req, res) => {
  const { search, category } = req.query;
  
  let query = 'SELECT * FROM products';
  let params = [];
  
  if (search || category) {
    query += ' WHERE';
    const conditions = [];
    
    if (search) {
      // VULNERABILITY: SQL injection via search parameter
      conditions.push(`(name LIKE '%${search}%' OR description LIKE '%${search}%')`);
    }
    
    if (category) {
      conditions.push(`category = ?`);
      params.push(category);
    }
    
    query += ' ' + conditions.join(' AND ');
  }
  
  db.all(query, params, (err, products) => {
    if (err) {
      return res.status(500).json({ 
        error: 'Database error', 
        details: err.message,
        query: query
      });
    }
    res.json(products);
  });
});

// Get single product
app.get('/api/products/:id', (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM products WHERE id = ?', [id], (err, product) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  });
});

// Get product reviews
app.get('/api/products/:id/reviews', (req, res) => {
  const { id } = req.params;
  
  db.all(`SELECT r.*, u.username FROM reviews r 
          JOIN users u ON r.user_id = u.id 
          WHERE r.product_id = ?`, [id], (err, reviews) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(reviews);
  });
});

// Add product review - VULNERABILITY: Stored XSS
app.post('/api/products/:id/reviews', (req, res) => {
  const { id } = req.params;
  const { review_text, rating } = req.body;
  const userId = req.session.userId;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // VULNERABILITY: No input sanitization - allows XSS
  db.run(`INSERT INTO reviews (product_id, user_id, review_text, rating) VALUES (?, ?, ?, ?)`,
    [id, userId, review_text, rating], function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, reviewId: this.lastID });
    });
});

// Create order
app.post('/api/orders', (req, res) => {
  const { items, total, customerInfo, paymentInfo } = req.body;
  const userId = req.session.userId;
  
  // VULNERABILITY: Storing sensitive payment data
  db.run(`INSERT INTO orders (user_id, total, customer_info, payment_info) VALUES (?, ?, ?, ?)`,
    [userId, total, JSON.stringify(customerInfo), JSON.stringify(paymentInfo)], 
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, orderId: this.lastID });
    });
});

// VULNERABILITY: IDOR - No access control on order details
app.get('/api/orders/:id', (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM orders WHERE id = ?', [id], (err, order) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // VULNERABILITY: Exposing sensitive data without authorization check
    res.json({
      ...order,
      customer_info: JSON.parse(order.customer_info),
      payment_info: JSON.parse(order.payment_info)
    });
  });
});

// Admin routes - VULNERABILITY: Weak authentication check
function isAdmin(req, res, next) {
  if (req.session.userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// VULNERABILITY: SQL injection in admin user search
app.get('/api/admin/users', isAdmin, (req, res) => {
  const { search } = req.query;
  
  let query = 'SELECT * FROM users';
  
  if (search) {
    // VULNERABILITY: Direct string interpolation
    query += ` WHERE username LIKE '%${search}%' OR email LIKE '%${search}%'`;
  }
  
  console.log('Admin query:', query);
  
  db.all(query, (err, users) => {
    if (err) {
      return res.status(500).json({ 
        error: 'Database error', 
        details: err.message,
        query: query
      });
    }
    res.json(users);
  });
});

// Get all orders (admin)
app.get('/api/admin/orders', isAdmin, (req, res) => {
  db.all(`SELECT o.*, u.username FROM orders o 
          LEFT JOIN users u ON o.user_id = u.id 
          ORDER BY o.created_at DESC`, (err, orders) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    const ordersWithParsedData = orders.map(order => ({
      ...order,
      customer_info: JSON.parse(order.customer_info),
      payment_info: JSON.parse(order.payment_info)
    }));
    
    res.json(ordersWithParsedData);
  });
});

// VULNERABILITY: Insecure file upload
app.post('/api/admin/upload', isAdmin, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // VULNERABILITY: No file type validation
    // VULNERABILITY: Path traversal possible
    res.json({ 
      success: true, 
      filename: req.file.filename,
      path: req.file.path,
      originalName: req.file.originalname
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Upload failed', 
      details: error.message,
      stack: error.stack
    });
  }
});

// VULNERABILITY: Path traversal in file download
app.get('/api/download/:filename', (req, res) => {
  const { filename } = req.params;
  
  // VULNERABILITY: No path validation
  const filePath = path.join(__dirname, filename);
  
  res.download(filePath, (err) => {
    if (err) {
      res.status(500).json({ 
        error: 'Download failed', 
        details: err.message,
        path: filePath
      });
    }
  });
});

// VULNERABILITY: Debug endpoint exposing sensitive information
app.get('/api/debug', (req, res) => {
  res.json({
    environment: process.env,
    session: req.session,
    headers: req.headers,
    database_location: './database/widgets.db',
    ftp_credentials: {
      username: 'jane',
      password: 'password123',
      server: 'ftp.widgets.com'
    }
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
🚨 VULNERABLE SERVER RUNNING 🚨
Port: ${PORT}
Environment: Development (Insecure)
Database: SQLite (./database/widgets.db)

⚠️  WARNING: This server contains intentional security vulnerabilities!
   Only use for educational purposes in isolated environments.

Default Accounts:
- admin:admin123 (Admin)
- jane:password123 (Admin)  
- demo:demo (User)

FTP Credentials: jane:password123
  `);
});

module.exports = app;