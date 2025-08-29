-- Initialize database schema
-- VULNERABILITY: No password hashing, no input validation

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,  -- VULNERABILITY: Plaintext passwords
  role TEXT DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME,
  failed_login_attempts INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL,
  category TEXT,
  image TEXT,
  in_stock BOOLEAN DEFAULT 1,
  admin_notes TEXT,  -- VULNERABILITY: Internal data exposed
  cost REAL,         -- VULNERABILITY: Cost information exposed
  supplier TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  total REAL NOT NULL,
  status TEXT DEFAULT 'pending',
  customer_info TEXT,    -- VULNERABILITY: Unencrypted PII
  payment_info TEXT,     -- VULNERABILITY: Unencrypted payment data
  shipping_address TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER,
  user_id INTEGER,
  review_text TEXT,      -- VULNERABILITY: No XSS protection
  rating INTEGER,
  is_approved BOOLEAN DEFAULT 0,
  admin_notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (product_id) REFERENCES products (id),
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER,
  data TEXT,
  expires_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Insert default admin users
INSERT OR IGNORE INTO users (username, email, password, role) VALUES 
  ('admin', 'admin@widgets.com', 'admin123', 'admin'),
  ('jane', 'jane@widgets.com', 'password123', 'admin'),
  ('demo', 'demo@test.com', 'demo', 'user'),
  ('test', 'test@test.com', 'test', 'user');

-- Insert sample products
INSERT OR IGNORE INTO products (name, description, price, category, image, admin_notes, cost, supplier) VALUES 
  ('Classic Red Widget', 'A beautiful handcrafted red widget perfect for any occasion.', 29.99, 'Classic', '/placeholder.svg', 'High profit margin item', 8.50, 'Widget Co Ltd'),
  ('Professional Blue Widget', 'The professional choice for serious widget enthusiasts.', 49.99, 'Professional', '/placeholder.svg', 'Customer favorite', 15.25, 'Pro Widgets Inc'),
  ('Deluxe Gold Widget', 'Our premium gold widget with luxury finish.', 89.99, 'Deluxe', '/placeholder.svg', 'Markup: 300%', 22.50, 'Luxury Widget Corp'),
  ('Eco-Friendly Green Widget', 'Sustainably made widget from recycled materials.', 34.99, 'Eco', '/placeholder.svg', 'Good for PR', 12.00, 'Green Widget Solutions'),
  ('Compact Mini Widget', 'Small but mighty! Our compact widget packs all the features.', 19.99, 'Mini', '/placeholder.svg', 'Cheapest to produce', 4.75, 'MiniTech Widgets'),
  ('Industrial Black Widget', 'Heavy-duty widget designed for industrial applications.', 119.99, 'Industrial', '/placeholder.svg', 'Government contract item', 45.00, 'Industrial Widget Systems');