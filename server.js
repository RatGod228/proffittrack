const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Try to load nodemailer
let nodemailer = null;
try {
  nodemailer = require('nodemailer');
  console.log('Nodemailer loaded successfully');
} catch (e) {
  console.log('Nodemailer not available, emails will be logged only');
}

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.DATA_DIR || '/tmp/data';

// SMTP Configuration from environment
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = parseInt(process.env.SMTP_PORT) || 587;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || 'noreply@profittrack.app';

console.log('=== ProfitTrack Server Starting ===');
console.log('Data directory:', DATA_DIR);
console.log('Current directory:', __dirname);
console.log('SMTP Host:', SMTP_HOST || 'Not configured');
console.log('SMTP User:', SMTP_USER || 'Not configured');

// Create email transporter if SMTP is configured
let emailTransporter = null;
if (nodemailer && SMTP_HOST && SMTP_USER && SMTP_PASS) {
  try {
    emailTransporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS
      }
    });
    console.log('Email transporter created successfully');
  } catch (err) {
    console.error('Failed to create email transporter:', err.message);
  }
} else {
  console.log('Email: Logging only mode (configure SMTP for real emails)');
}

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Database files
const DB = {
  users: path.join(DATA_DIR, 'users.json'),
  purchases: path.join(DATA_DIR, 'purchases.json'),
  sales: path.join(DATA_DIR, 'sales.json'),
  branches: path.join(DATA_DIR, 'branches.json'),
  resetCodes: path.join(DATA_DIR, 'resetCodes.json'),
  reviews: path.join(DATA_DIR, 'reviews.json')
};

// Initialize DB files
Object.values(DB).forEach(file => {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, '[]');
    console.log('Created:', path.basename(file));
  }
});

// Check public directory
const PUBLIC_DIR = path.join(__dirname, 'public');
console.log('Public directory:', PUBLIC_DIR);
console.log('Public exists:', fs.existsSync(PUBLIC_DIR));

if (fs.existsSync(PUBLIC_DIR)) {
  const files = fs.readdirSync(PUBLIC_DIR);
  console.log('Public files:', files);
}

// Send email function
const sendEmail = async (to, subject, text) => {
  console.log('=== EMAIL ===');
  console.log('To:', to);
  console.log('Subject:', subject);
  console.log('Body:', text);
  console.log('=============');
  
  if (emailTransporter) {
    try {
      const info = await emailTransporter.sendMail({
        from: `"ProfitTrack" <${SMTP_FROM}>`,
        to: to,
        subject: subject,
        text: text,
        html: `<pre>${text}</pre>`
      });
      console.log('Email sent successfully! Message ID:', info.messageId);
      return { sent: true, messageId: info.messageId };
    } catch (err) {
      console.error('Failed to send email:', err.message);
      return { sent: false, error: err.message };
    }
  }
  
  return { sent: false, reason: 'SMTP not configured' };
};

// Password hashing
const hashPassword = (pwd) => crypto.createHash('sha256').update(pwd + JWT_SECRET).digest('hex');

// JWT functions
const generateToken = (user) => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ 
    id: user.id, 
    login: user.login, 
    email: user.email, 
    name: user.name, 
    iat: Date.now(),
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + payload).digest('base64url');
  return header + '.' + payload + '.' + signature;
};

const verifyToken = (token) => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(parts[0] + '.' + parts[1]).digest('base64url');
    if (parts[2] !== expected) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch (e) { return null; }
};

// CORS headers
const setCORS = (res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

// Parse request body
const parseBody = (req) => new Promise((resolve, reject) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try { resolve(body ? JSON.parse(body) : {}); } 
    catch (e) { reject(e); }
  });
});

// Get authenticated user
const getAuthUser = (req) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const decoded = verifyToken(auth.substring(7));
  if (!decoded) return null;
  const users = JSON.parse(fs.readFileSync(DB.users, 'utf8') || '[]');
  return users.find(u => u.id === decoded.id);
};

// DB helpers
const readDB = (dbName) => {
  try { return JSON.parse(fs.readFileSync(DB[dbName], 'utf8') || '[]'); } 
  catch (e) { return []; }
};

const writeDB = (dbName, data) => {
  fs.writeFileSync(DB[dbName], JSON.stringify(data, null, 2));
};

// Serve index.html
const serveIndex = (res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  console.log('Serving index from:', indexPath);
  
  try {
    if (fs.existsSync(indexPath)) {
      const content = fs.readFileSync(indexPath);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
      console.log('Index served successfully');
    } else {
      console.error('index.html not found at:', indexPath);
      res.writeHead(404);
      res.end('index.html not found');
    }
  } catch (e) {
    console.error('Error serving index:', e);
    res.writeHead(500);
    res.end('Server error');
  }
};

// API Routes
const routes = {
  'POST /api/auth/register': async (req, res) => {
    try {
      const { name, login, password, email } = await parseBody(req);
      if (!name || !login || !password) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Заполните все поля' }));
      }
      if (!email) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Email обязателен' }));
      }
      
      const users = readDB('users');
      if (users.find(u => u.login === login)) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Логин уже занят' }));
      }
      if (users.find(u => u.email === email)) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Email уже используется' }));
      }
      
      const newUser = { 
        id: crypto.randomUUID(), 
        name, 
        login, 
        email, 
        password: hashPassword(password), 
        createdAt: new Date().toISOString() 
      };
      users.push(newUser);
      writeDB('users', users);
      
      // Create default branch
      const branches = readDB('branches');
      branches.push({
        id: crypto.randomUUID(),
        userId: newUser.id,
        name: 'Основная ветка',
        createdAt: new Date().toISOString()
      });
      writeDB('branches', branches);
      
      const token = generateToken(newUser);
      res.writeHead(201); 
      res.end(JSON.stringify({ token, user: { id: newUser.id, name, login, email } }));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'POST /api/auth/login': async (req, res) => {
    try {
      const { login, password } = await parseBody(req);
      const users = readDB('users');
      const user = users.find(u => u.login === login && u.password === hashPassword(password));
      if (!user) {
        res.writeHead(401); 
        return res.end(JSON.stringify({ error: 'Неверный логин или пароль' }));
      }
      const token = generateToken(user);
      res.writeHead(200); 
      res.end(JSON.stringify({ token, user: { id: user.id, name: user.name, login: user.login, email: user.email } }));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'POST /api/auth/forgot-password': async (req, res) => {
    try {
      const { email } = await parseBody(req);
      const users = readDB('users');
      const user = users.find(u => u.email === email);
      if (!user) {
        res.writeHead(404); 
        return res.end(JSON.stringify({ error: 'Email не найден' }));
      }
      
      const code = Math.random().toString(36).substring(2, 8).toUpperCase();
      const resetCodes = readDB('resetCodes');
      const filtered = resetCodes.filter(c => c.email !== email);
      filtered.push({ email, code, expiresAt: Date.now() + 15 * 60 * 1000 });
      writeDB('resetCodes', filtered);
      
      // Send email
      const emailResult = await sendEmail(
        email, 
        'Восстановление пароля - ProfitTrack', 
        `Здравствуйте, ${user.name}!\n\nВаш код подтверждения: ${code}\n\nКод действителен 15 минут.\n\nЕсли вы не запрашивали восстановление пароля, проигнорируйте это письмо.`
      );
      
      if (emailResult.sent) {
        res.writeHead(200); 
        res.end(JSON.stringify({ message: 'Код отправлен на ваш email' }));
      } else {
        // If email not sent, return code in response for testing
        res.writeHead(200); 
        res.end(JSON.stringify({ 
          message: 'Код отправлен (проверьте логи сервера если email не пришел)',
          code: code  // Only for testing when SMTP not configured
        }));
      }
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'POST /api/auth/verify-code': async (req, res) => {
    try {
      const { email, code } = await parseBody(req);
      const resetCodes = readDB('resetCodes');
      const resetCode = resetCodes.find(c => c.email === email && c.code === code.toUpperCase());
      if (!resetCode || Date.now() > resetCode.expiresAt) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Неверный код' }));
      }
      res.writeHead(200); 
      res.end(JSON.stringify({ message: 'Код подтвержден' }));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'POST /api/auth/reset-password': async (req, res) => {
    try {
      const { email, code, newPassword } = await parseBody(req);
      if (!newPassword || newPassword.length < 4) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Пароль минимум 4 символа' }));
      }
      
      const resetCodes = readDB('resetCodes');
      const resetCode = resetCodes.find(c => c.email === email && c.code === code.toUpperCase());
      if (!resetCode || Date.now() > resetCode.expiresAt) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Неверный код' }));
      }
      
      const users = readDB('users');
      const idx = users.findIndex(u => u.email === email);
      if (idx === -1) {
        res.writeHead(404); 
        return res.end(JSON.stringify({ error: 'Пользователь не найден' }));
      }
      
      users[idx].password = hashPassword(newPassword);
      writeDB('users', users);
      writeDB('resetCodes', resetCodes.filter(c => c.code !== code.toUpperCase()));
      
      res.writeHead(200); 
      res.end(JSON.stringify({ message: 'Пароль изменен' }));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'POST /api/auth/change-password': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    try {
      const { currentPassword, newPassword } = await parseBody(req);
      const users = readDB('users');
      const idx = users.findIndex(u => u.id === user.id);
      if (users[idx].password !== hashPassword(currentPassword)) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Неверный пароль' }));
      }
      users[idx].password = hashPassword(newPassword);
      writeDB('users', users);
      res.writeHead(200); 
      res.end(JSON.stringify({ message: 'Пароль изменен' }));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'GET /api/user/profile': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    res.writeHead(200); 
    res.end(JSON.stringify({ id: user.id, name: user.name, login: user.login, email: user.email }));
  },
  
  'GET /api/branches': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const branches = readDB('branches').filter(b => b.userId === user.id);
    res.writeHead(200); 
    res.end(JSON.stringify(branches));
  },
  
  'POST /api/branches': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    try {
      const { name } = await parseBody(req);
      const branches = readDB('branches');
      const newBranch = { id: crypto.randomUUID(), userId: user.id, name, createdAt: new Date().toISOString() };
      branches.push(newBranch);
      writeDB('branches', branches);
      res.writeHead(201); 
      res.end(JSON.stringify(newBranch));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'DELETE /api/branches/:id': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const branches = readDB('branches');
    const userBranches = branches.filter(b => b.userId === user.id);
    if (userBranches.length <= 1) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Нельзя удалить последнюю ветку' }));
    }
    
    writeDB('branches', branches.filter(b => b.id !== id || b.userId !== user.id));
    const purchases = readDB('purchases');
    writeDB('purchases', purchases.filter(p => p.branchId !== id || p.userId !== user.id));
    const sales = readDB('sales');
    writeDB('sales', sales.filter(s => s.branchId !== id || s.userId !== user.id));
    
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Ветка удалена' }));
  },
  
  'GET /api/purchases': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const purchases = readDB('purchases').filter(p => p.userId === user.id);
    res.writeHead(200); 
    res.end(JSON.stringify(purchases));
  },
  
  'POST /api/purchases': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    try {
      const { productName, quantity, price, date, branchId, photo, notes } = await parseBody(req);
      const qty = parseInt(quantity);
      const purchases = readDB('purchases');
      const newPurchase = {
        id: crypto.randomUUID(),
        userId: user.id,
        productName: productName.trim(),
        quantity: qty,
        remainingQty: qty,
        price: parseFloat(price),
        total: qty * parseFloat(price),
        date: date || new Date().toISOString().split('T')[0],
        branchId,
        photo: photo || undefined,
        notes: notes ? notes.trim() : undefined,
        createdAt: new Date().toISOString()
      };
      purchases.push(newPurchase);
      writeDB('purchases', purchases);
      res.writeHead(201); 
      res.end(JSON.stringify(newPurchase));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'DELETE /api/purchases/:id': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const purchases = readDB('purchases');
    writeDB('purchases', purchases.filter(p => p.id !== id || p.userId !== user.id));
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Закупка удалена' }));
  },
  
  'PUT /api/purchases/:id/notes': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    try {
      const { notes } = await parseBody(req);
      const purchases = readDB('purchases');
      const idx = purchases.findIndex(p => p.id === id && p.userId === user.id);
      if (idx === -1) {
        res.writeHead(404); 
        return res.end(JSON.stringify({ error: 'Не найдено' }));
      }
      purchases[idx].notes = notes ? notes.trim() : undefined;
      writeDB('purchases', purchases);
      res.writeHead(200); 
      res.end(JSON.stringify(purchases[idx]));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'GET /api/sales': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const sales = readDB('sales').filter(s => s.userId === user.id);
    res.writeHead(200); 
    res.end(JSON.stringify(sales));
  },
  
  'POST /api/sales': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    try {
      const { productName, quantity, salePrice, date, branchId, notes } = await parseBody(req);
      const qty = parseInt(quantity);
      const sPrice = parseFloat(salePrice);
      
      const purchases = readDB('purchases');
      const relevantPurchases = purchases.filter(p => 
        p.userId === user.id &&
        p.branchId === branchId && 
        p.productName === productName && 
        p.remainingQty > 0
      ).sort((a, b) => new Date(a.date) - new Date(b.date));
      
      const totalRemaining = relevantPurchases.reduce((sum, p) => sum + p.remainingQty, 0);
      if (totalRemaining < qty) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: `Недостаточно товара! Осталось: ${totalRemaining} шт.` }));
      }
      
      let remainingToDeduct = qty;
      const updatedPurchases = purchases.map(p => {
        if (remainingToDeduct <= 0) return p;
        if (p.userId !== user.id || p.branchId !== branchId || p.productName !== productName || p.remainingQty <= 0) return p;
        const deductQty = Math.min(p.remainingQty, remainingToDeduct);
        remainingToDeduct -= deductQty;
        return { ...p, remainingQty: p.remainingQty - deductQty };
      });
      
      writeDB('purchases', updatedPurchases);
      
      const firstPurchase = relevantPurchases[0];
      const purchasePrice = firstPurchase?.price || 0;
      
      const newSale = {
        id: crypto.randomUUID(),
        userId: user.id,
        productName: productName.trim(),
        quantity: qty,
        purchasePrice: purchasePrice,
        salePrice: sPrice,
        totalCost: qty * purchasePrice,
        totalRevenue: qty * sPrice,
        profit: qty * (sPrice - purchasePrice),
        date: date || new Date().toISOString().split('T')[0],
        branchId,
        purchaseId: firstPurchase?.id || '',
        photo: firstPurchase?.photo,
        notes: notes ? notes.trim() : undefined,
        createdAt: new Date().toISOString()
      };
      
      const sales = readDB('sales');
      sales.push(newSale);
      writeDB('sales', sales);
      res.writeHead(201); 
      res.end(JSON.stringify(newSale));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'DELETE /api/sales/:id': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const sales = readDB('sales');
    writeDB('sales', sales.filter(s => s.id !== id || s.userId !== user.id));
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Продажа удалена' }));
  },
  
  'PUT /api/sales/:id/notes': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    try {
      const { notes } = await parseBody(req);
      const sales = readDB('sales');
      const idx = sales.findIndex(s => s.id === id && s.userId === user.id);
      if (idx === -1) {
        res.writeHead(404); 
        return res.end(JSON.stringify({ error: 'Не найдено' }));
      }
      sales[idx].notes = notes ? notes.trim() : undefined;
      writeDB('sales', sales);
      res.writeHead(200); 
      res.end(JSON.stringify(sales[idx]));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  },
  
  'GET /api/reviews': async (req, res) => {
    const reviews = readDB('reviews').sort((a, b) => new Date(b.date) - new Date(a.date));
    res.writeHead(200); 
    res.end(JSON.stringify(reviews));
  },
  
  'POST /api/reviews': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    try {
      const { rating, text } = await parseBody(req);
      const reviews = readDB('reviews');
      const newReview = {
        id: crypto.randomUUID(),
        userId: user.id,
        name: user.name,
        rating,
        text: text.trim(),
        date: new Date().toISOString().split('T')[0]
      };
      reviews.push(newReview);
      writeDB('reviews', reviews);
      res.writeHead(201); 
      res.end(JSON.stringify(newReview));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  }
};

// Create server
const server = http.createServer(async (req, res) => {
  setCORS(res);
  if (req.method === 'OPTIONS') { 
    res.writeHead(200); 
    return res.end(); 
  }
  
  const pathname = req.url.split('?')[0];
  console.log(`${req.method} ${pathname}`);
  
  // API routes
  for (const routeKey of Object.keys(routes)) {
    const [method, pathPattern] = routeKey.split(' ');
    if (req.method === method) {
      if (pathPattern.includes('/:')) {
        const basePath = pathPattern.split('/:')[0];
        if (pathname.startsWith(basePath + '/')) {
          const id = pathname.substring(basePath.length + 1);
          try {
            await routes[routeKey](req, res, id);
            return;
          } catch (e) {
            console.error('Route error:', e);
            res.writeHead(500); 
            return res.end(JSON.stringify({ error: 'Server error' }));
          }
        }
      } else if (pathname === pathPattern) {
        try {
          await routes[routeKey](req, res);
          return;
        } catch (e) {
          console.error('Route error:', e);
          res.writeHead(500); 
          return res.end(JSON.stringify({ error: 'Server error' }));
        }
      }
    }
  }
  
  // Serve static files
  if (pathname === '/' || pathname === '/index.html') {
    return serveIndex(res);
  }
  
  // Fallback to index for client-side routing
  serveIndex(res);
});

server.listen(PORT, () => {
  console.log('Server running on port', PORT);
});
