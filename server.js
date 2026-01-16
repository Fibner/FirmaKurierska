const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'courier_saas_main',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool.getConnection()
  .then(connection => {
    console.log('Połączono z bazą danych MySQL');
    connection.release();
  })
  .catch(err => {
    console.error('Błąd połączenia z bazą:', err.message);
  });


const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Brak tokenu uwierzytelniającego' });

  jwt.verify(token, process.env.JWT_SECRET || 'secret_key_change_in_production', (err, user) => {
    if (err) return res.status(403).json({ error: 'Nieprawidłowy token' });
    req.user = user;
    next();
  });
};

const identifyTenant = (req, res, next) => {
  const tenantId = req.headers['x-tenant-id'];

  if (!tenantId) return res.status(400).json({ error: 'Brak identyfikatora firmy (X-Tenant-ID)' });
  if (!/^[a-zA-Z0-9_]{1,20}$/.test(tenantId)) return res.status(400).json({ error: 'Nieprawidłowy format tenant ID' });

  req.tenantSchema = `tenant_${tenantId}`;
  req.tenantId = tenantId;
  next();
};
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Brak uprawnień' });
    next();
  };
};


const ORDER_STATUSES = ['pending','assigned','picked_up','in_transit','delivered','failed_delivery','cancelled'];

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function normalizeOrderPayload(body) {
  if (body && body.sender && body.recipient && body.packageDetails) {
    return {
      sender: {
        name: body.sender.name,
        address: body.sender.address,
        phone: body.sender.phone || null
      },
      recipient: {
        name: body.recipient.name,
        address: body.recipient.address,
        phone: body.recipient.phone || null
      },
      packageDetails: {
        weight: Number(body.packageDetails.weight),
        dimensions: body.packageDetails.dimensions || {},
        value: Number(body.packageDetails.value || 0)
      },
      deliveryType: body.deliveryType || 'standard'
    };
  }

  return {
    sender: { name: body.senderName, address: body.senderAddress, phone: body.senderPhone || null },
    recipient: { name: body.recipientName, address: body.recipientAddress, phone: body.recipientPhone || null },
    packageDetails: {
      weight: Number(body.weight),
      dimensions: body.dimensions || {},
      value: Number(body.value || 0)
    },
    deliveryType: body.deliveryType || 'standard'
  };
}

function validateOrderPayload(p) {
  const errors = [];
  if (!isNonEmptyString(p.sender?.name)) errors.push('Brak nadawcy');
  if (!isNonEmptyString(p.sender?.address)) errors.push('Brak adresu nadawcy');
  if (!isNonEmptyString(p.recipient?.name)) errors.push('Brak odbiorcy');
  if (!isNonEmptyString(p.recipient?.address)) errors.push('Brak adresu odbiorcy');

  if (!Number.isFinite(p.packageDetails?.weight) || p.packageDetails.weight <= 0) errors.push('Nieprawidłowa waga przesyłki');
  const allowedDelivery = ['standard','express','overnight'];
  if (p.deliveryType && !allowedDelivery.includes(p.deliveryType)) errors.push('Nieprawidłowy typ dostawy');

  return errors;
}

async function ensureStatusHistoryTable(connection, schema) {
  await connection.query(
    `CREATE TABLE IF NOT EXISTS ${schema}.order_status_history (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      order_id BIGINT NOT NULL,
      status VARCHAR(32) NOT NULL,
      changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      changed_by BIGINT NULL,
      note VARCHAR(255) NULL,
      INDEX idx_order_id (order_id),
      INDEX idx_changed_at (changed_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`
  );
}

async function addStatusHistory(connection, schema, { orderId, status, changedBy, note }) {
  await ensureStatusHistoryTable(connection, schema);
  await connection.query(
    `INSERT INTO ${schema}.order_status_history (order_id, status, changed_by, note)
     VALUES (?, ?, ?, ?)`,
    [orderId, status, changedBy || null, note || null]
  );
}


async function assignOptimalCourier(connection, schema) {
  const [couriers] = await connection.query(
    `SELECT 
      c.id,
      CONCAT(u.first_name, ' ', u.last_name) as name,
      c.vehicle_type,
      c.max_capacity,
      c.rating,
      COUNT(o.id) as current_orders,
      COALESCE(SUM(p.weight), 0) as current_weight
     FROM ${schema}.couriers c
     JOIN ${schema}.users u ON c.user_id = u.id
     LEFT JOIN ${schema}.orders o 
       ON c.id = o.courier_id 
       AND o.status IN ('assigned', 'picked_up', 'in_transit')
     LEFT JOIN ${schema}.packages p ON o.id = p.order_id
     WHERE c.is_available = 1 
       AND c.shift_end > NOW()
     GROUP BY c.id
     HAVING current_weight < c.max_capacity OR current_weight IS NULL
     ORDER BY 
       current_orders ASC,
       c.rating DESC
     LIMIT 1`
  );

  return couriers[0] || null;
}

function calculatePrice(weight, deliveryType) {
  const basePrice = weight * 2.50;
  const multipliers = { standard: 1.0, express: 1.5, overnight: 2.0 };
  return Math.round(basePrice * (multipliers[deliveryType] || 1.0) * 100) / 100;
}

function predictNextWeek(historicalData) {
  if (historicalData.length < 7) return [];

  const lastWeek = historicalData.slice(-7);
  const avg = lastWeek.reduce((sum, d) => sum + d.orders_count, 0) / 7;

  const firstHalf = lastWeek.slice(0, 3).reduce((s, d) => s + d.orders_count, 0) / 3;
  const secondHalf = lastWeek.slice(4, 7).reduce((s, d) => s + d.orders_count, 0) / 3;
  const trend = (secondHalf - firstHalf) / 7;

  return Array.from({ length: 7 }, (_, i) => ({
    day: i + 1,
    date: new Date(Date.now() + (i + 1) * 86400000).toISOString().split('T')[0],
    predicted_orders: Math.max(0, Math.round(avg + trend * (i + 1)))
  }));
}

app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString(), uptime: process.uptime() });
});


app.post('/api/auth/login', async (req, res) => {
  const { email, password, tenantId } = req.body;
  const schema = `tenant_${tenantId}`;

  try {
    const [users] = await pool.query(`SELECT * FROM ${schema}.users WHERE email = ?`, [email]);
    if (users.length === 0) return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'secret_key_change_in_production',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        firstName: user.first_name,
        lastName: user.last_name
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.post('/api/orders',
  authenticateToken,
  identifyTenant,
  async (req, res) => {
    const connection = await pool.getConnection();

    try {
      const payload = normalizeOrderPayload(req.body);
      const errors = validateOrderPayload(payload);
      if (errors.length) return res.status(400).json({ error: 'Błędne dane zamówienia', details: errors });

      await connection.beginTransaction();

      const orderNumber = `ORD${Date.now()}${Math.floor(Math.random() * 1000)}`;

      const [orderResult] = await connection.query(
        `INSERT INTO ${req.tenantSchema}.orders 
         (order_number, sender_name, sender_address, sender_phone,
          recipient_name, recipient_address, recipient_phone,
          status, created_at, created_by) 
         VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NOW(), ?)`,
        [
          orderNumber,
          payload.sender.name, payload.sender.address, payload.sender.phone || null,
          payload.recipient.name, payload.recipient.address, payload.recipient.phone || null,
          req.user.id
        ]
      );

      const orderId = orderResult.insertId;

      await connection.query(
        `INSERT INTO ${req.tenantSchema}.packages 
         (order_id, weight, dimensions, declared_value, delivery_type) 
         VALUES (?, ?, ?, ?, ?)`,
        [
          orderId,
          payload.packageDetails.weight,
          JSON.stringify(payload.packageDetails.dimensions || {}),
          payload.packageDetails.value || 0,
          payload.deliveryType || 'standard'
        ]
      );

      await addStatusHistory(connection, req.tenantSchema, {
        orderId,
        status: 'pending',
        changedBy: req.user.id,
        note: 'Utworzenie zamówienia'
      });

      const courier = await assignOptimalCourier(connection, req.tenantSchema);

      if (courier) {
        await connection.query(
          `UPDATE ${req.tenantSchema}.orders 
           SET courier_id = ?, status = 'assigned' 
           WHERE id = ?`,
          [courier.id, orderId]
        );

        await addStatusHistory(connection, req.tenantSchema, {
          orderId,
          status: 'assigned',
          changedBy: req.user.id,
          note: `Automatyczny przydział kuriera: ${courier.name}`
        });
      }

      await connection.commit();

      res.json({
        success: true,
        orderId,
        orderNumber,
        courierId: courier?.id,
        courierName: courier?.name,
        status: courier ? 'assigned' : 'pending'
      });

    } catch (error) {
      try { await connection.rollback(); } catch (_) {}
      res.status(500).json({ error: error.message });
    } finally {
      connection.release();
    }
  }
);

app.patch('/api/orders/:id/assign',
  authenticateToken,
  identifyTenant,
  authorize('admin', 'manager'),
  async (req, res) => {
    const { courierId } = req.body;
    const orderId = Number(req.params.id);

    if (!Number.isInteger(orderId) || orderId <= 0) return res.status(400).json({ error: 'Nieprawidłowe ID zamówienia' });
    if (!Number.isInteger(Number(courierId)) || Number(courierId) <= 0) return res.status(400).json({ error: 'Nieprawidłowe courierId' });

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      const [orders] = await connection.query(
        `SELECT id, status FROM ${req.tenantSchema}.orders WHERE id = ?`,
        [orderId]
      );
      if (orders.length === 0) return res.status(404).json({ error: 'Zamówienie nie znalezione' });

      await connection.query(
        `UPDATE ${req.tenantSchema}.orders SET courier_id = ?, status = 'assigned' WHERE id = ?`,
        [Number(courierId), orderId]
      );

      await addStatusHistory(connection, req.tenantSchema, {
        orderId,
        status: 'assigned',
        changedBy: req.user.id,
        note: `Ręczny przydział kuriera (courier_id=${Number(courierId)})`
      });

      await connection.commit();
      res.json({ success: true });

    } catch (error) {
      try { await connection.rollback(); } catch (_) {}
      res.status(500).json({ error: error.message });
    } finally {
      connection.release();
    }
  }
);

app.patch('/api/orders/:id/status',
  authenticateToken,
  identifyTenant,
  async (req, res) => {
    const orderId = Number(req.params.id);
    const { status, note } = req.body;

    if (!Number.isInteger(orderId) || orderId <= 0) return res.status(400).json({ error: 'Nieprawidłowe ID zamówienia' });
    if (!ORDER_STATUSES.includes(status)) return res.status(400).json({ error: 'Nieprawidłowy status' });

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      const [rows] = await connection.query(
        `SELECT id, status, courier_id FROM ${req.tenantSchema}.orders WHERE id = ?`,
        [orderId]
      );
      if (!rows.length) return res.status(404).json({ error: 'Zamówienie nie znalezione' });

      const order = rows[0];

      if (status === 'cancelled' && !['pending','assigned'].includes(order.status)) {
        return res.status(400).json({ error: 'Nie można anulować po odebraniu przesyłki' });
      }

      const deliveredAtSql = (status === 'delivered') ? ', delivered_at = NOW()' : '';
      await connection.query(
        `UPDATE ${req.tenantSchema}.orders SET status = ?${deliveredAtSql} WHERE id = ?`,
        [status, orderId]
      );

      await addStatusHistory(connection, req.tenantSchema, {
        orderId,
        status,
        changedBy: req.user.id,
        note: note || null
      });

      await connection.commit();
      res.json({ success: true });

    } catch (error) {
      try { await connection.rollback(); } catch (_) {}
      res.status(500).json({ error: error.message });
    } finally {
      connection.release();
    }
  }
);

app.get('/api/orders/:id/history',
  authenticateToken,
  identifyTenant,
  async (req, res) => {
    const orderId = Number(req.params.id);
    if (!Number.isInteger(orderId) || orderId <= 0) return res.status(400).json({ error: 'Nieprawidłowe ID zamówienia' });

    try {
      const connection = await pool.getConnection();
      try {
        await ensureStatusHistoryTable(connection, req.tenantSchema);
        const [hist] = await connection.query(
          `SELECT id, status, changed_at, changed_by, note
           FROM ${req.tenantSchema}.order_status_history
           WHERE order_id = ?
           ORDER BY changed_at ASC, id ASC`,
          [orderId]
        );
        res.json(hist);
      } finally {
        connection.release();
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get('/api/orders/:id/track',
  identifyTenant,
  async (req, res) => {
    try {
      const [rows] = await pool.query(
        `SELECT 
          o.*, p.*,
          c.vehicle_type,
          CONCAT(u.first_name, ' ', u.last_name) as courier_name,
          u.phone as courier_phone
         FROM ${req.tenantSchema}.orders o
         LEFT JOIN ${req.tenantSchema}.packages p ON o.id = p.order_id
         LEFT JOIN ${req.tenantSchema}.couriers c ON o.courier_id = c.id
         LEFT JOIN ${req.tenantSchema}.users u ON c.user_id = u.id
         WHERE o.id = ?`,
        [req.params.id]
      );

      if (rows.length === 0) return res.status(404).json({ error: 'Zamówienie nie znalezione' });
      res.json(rows[0]);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get('/api/orders',
  authenticateToken,
  identifyTenant,
  async (req, res) => {
    try {
      const { status, courier, client, startDate, endDate, limit = 50, offset = 0 } = req.query;

      let query = `
        SELECT 
          o.id, o.order_number, o.status,
          o.sender_name, o.recipient_name,
          o.created_at, o.delivered_at,
          p.weight, p.delivery_type,
          CONCAT(u.first_name, ' ', u.last_name) as courier_name
        FROM ${req.tenantSchema}.orders o
        LEFT JOIN ${req.tenantSchema}.packages p ON o.id = p.order_id
        LEFT JOIN ${req.tenantSchema}.couriers c ON o.courier_id = c.id
        LEFT JOIN ${req.tenantSchema}.users u ON c.user_id = u.id
        WHERE 1=1
      `;

      const params = [];

      if (status) { query += ` AND o.status = ?`; params.push(status); }
      if (courier) { query += ` AND CONCAT(u.first_name, ' ', u.last_name) LIKE ?`; params.push(`%${courier}%`); }
      if (client) { query += ` AND (o.sender_name LIKE ? OR o.recipient_name LIKE ?)`; params.push(`%${client}%`, `%${client}%`); }
      if (startDate) { query += ` AND o.created_at >= ?`; params.push(startDate); }
      if (endDate) { query += ` AND o.created_at <= ?`; params.push(endDate); }

      query += ` ORDER BY o.created_at DESC LIMIT ? OFFSET ?`;
      params.push(parseInt(limit), parseInt(offset));

      const [rows] = await pool.query(query, params);
      res.json(rows);

    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);


app.post('/api/invoices/generate',
  authenticateToken,
  identifyTenant,
  async (req, res) => {
    const { orderId } = req.body;

    try {
      const [orders] = await pool.query(
        `SELECT o.*, p.weight, p.delivery_type
         FROM ${req.tenantSchema}.orders o
         JOIN ${req.tenantSchema}.packages p ON o.id = p.order_id
         WHERE o.id = ?`,
        [orderId]
      );

      if (orders.length === 0) return res.status(404).json({ error: 'Zamówienie nie znalezione' });

      const order = orders[0];
      const price = calculatePrice(order.weight, order.delivery_type);
      const taxRate = 0.23;
      const totalAmount = price * (1 + taxRate);

      const invoiceNumber = `INV${Date.now()}`;

      const [result] = await pool.query(
        `INSERT INTO ${req.tenantSchema}.invoices 
         (invoice_number, order_id, amount, tax_rate, total_amount, 
          issue_date, due_date, status)
         VALUES (?, ?, ?, ?, ?, CURDATE(), DATE_ADD(CURDATE(), INTERVAL 14 DAY), 'issued')`,
        [invoiceNumber, orderId, price, taxRate, totalAmount]
      );

      res.json({ invoiceId: result.insertId, invoiceNumber, amount: price, tax: price * taxRate, totalAmount });

    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);


app.get('/api/reports/orders.csv',
  authenticateToken,
  identifyTenant,
  authorize('admin', 'manager'),
  async (req, res) => {
    const { startDate, endDate } = req.query;

    try {
      const [rows] = await pool.query(
        `SELECT o.order_number, o.status, o.sender_name, o.recipient_name, o.created_at, o.delivered_at, 
                p.weight, p.delivery_type
         FROM ${req.tenantSchema}.orders o
         LEFT JOIN ${req.tenantSchema}.packages p ON o.id = p.order_id
         WHERE (? IS NULL OR o.created_at >= ?)
           AND (? IS NULL OR o.created_at <= ?)
         ORDER BY o.created_at DESC`,
        [startDate || null, startDate || null, endDate || null, endDate || null]
      );

      const header = ['order_number','status','sender_name','recipient_name','created_at','delivered_at','weight','delivery_type'];
      const escape = (v) => {
        if (v === null || v === undefined) return '';
        const s = String(v).replace(/"/g, '""');
        return /[",\n]/.test(s) ? `"${s}"` : s;
      };

      const lines = [header.join(',')].concat(rows.map(r => header.map(k => escape(r[k])).join(',')));

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="orders.csv"');
      res.send(lines.join('\n'));

    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);


app.get('/api/analytics/kpi',
  authenticateToken,
  identifyTenant,
  async (req, res) => {
    const { startDate, endDate } = req.query;

    try {
      const [ordersStats] = await pool.query(
        `SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as delivered,
          SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled,
          AVG(TIMESTAMPDIFF(HOUR, created_at, delivered_at)) as avg_delivery_hours
         FROM ${req.tenantSchema}.orders
         WHERE created_at BETWEEN ? AND ?`,
        [startDate, endDate]
      );

      const [revenueStats] = await pool.query(
        `SELECT 
          SUM(total_amount) as total_revenue,
          SUM(CASE WHEN status = 'paid' THEN total_amount ELSE 0 END) as paid_revenue
         FROM ${req.tenantSchema}.invoices
         WHERE issue_date BETWEEN ? AND ?`,
        [startDate, endDate]
      );

      const [courierStats] = await pool.query(
        `SELECT 
          c.id,
          CONCAT(u.first_name, ' ', u.last_name) as name,
          COUNT(o.id) as deliveries,
          c.rating
         FROM ${req.tenantSchema}.couriers c
         JOIN ${req.tenantSchema}.users u ON c.user_id = u.id
         LEFT JOIN ${req.tenantSchema}.orders o 
           ON c.id = o.courier_id 
           AND o.delivered_at BETWEEN ? AND ?
         GROUP BY c.id
         ORDER BY deliveries DESC
         LIMIT 10`,
        [startDate, endDate]
      );

      res.json({ orders: ordersStats[0], revenue: revenueStats[0], topCouriers: courierStats });

    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get('/api/analytics/forecast',
  authenticateToken,
  identifyTenant,
  async (req, res) => {
    try {
      const [historical] = await pool.query(
        `SELECT DATE(created_at) as date, COUNT(*) as orders_count
         FROM ${req.tenantSchema}.orders
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
         GROUP BY DATE(created_at)
         ORDER BY date`
      );

      const forecast = predictNextWeek(historical);

      res.json({ historical, forecast, algorithm: 'Moving Average with Trend Analysis' });

    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Database: ${process.env.DB_HOST || 'localhost'}`);
});

module.exports = app;
