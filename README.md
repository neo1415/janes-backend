# Jane's Widgets Backend - Intentionally Vulnerable Node.js Server

⚠️ **SECURITY WARNING: This server contains INTENTIONAL security vulnerabilities for educational purposes only. Do NOT deploy to production or use in any live environment.**

## Project Structure

```
janes-widgets-backend/
├── package.json
├── server.js
├── database/
│   ├── init.sql
│   └── widgets.db (auto-created)
├── routes/
│   ├── auth.js
│   ├── products.js
│   ├── orders.js
│   └── admin.js
├── middleware/
│   └── cors.js
├── uploads/
│   └── (user uploaded files)
├── ftp_credentials.txt
└── README.md
```

## Quick Start

1. Create the backend directory: `mkdir janes-widgets-backend && cd janes-widgets-backend`
2. Copy all the files I'll provide below
3. Install dependencies: `npm install`
4. Start the server: `npm start`
5. Server runs on `http://localhost:3001`

## Default Accounts

- FTP: `jane` / `password123`
- Admin: `admin` / `admin123`
- Demo User: `demo` / `demo`

## Intentional Vulnerabilities

1. **SQL Injection** - User search and login endpoints
2. **File Upload Vulnerabilities** - No validation, directory traversal
3. **Exposed FTP Credentials** - Plain text file in root
4. **Verbose Error Messages** - Stack traces in responses
5. **No Input Validation** - Direct database queries
6. **Weak Authentication** - Plaintext passwords
7. **CORS Misconfiguration** - Allows all origins
8. **Path Traversal** - File download endpoints
9. **Information Disclosure** - Debug endpoints exposed
10. **No Rate Limiting** - Brute force attacks possible

Connect your React frontend to `http://localhost:3001` or your Render deployment URL.