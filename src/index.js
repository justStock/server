import express from 'express';
import http from 'http';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import mongoose from 'mongoose';

import { connectDB } from './config/db.js';
import authRoutes from './routes/auth.js';
import adviceRoutes from './routes/advice.js';
import walletRoutes from './routes/wallet.js';

dotenv.config();

function parseOrigins(value) {
  return String(value || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

const httpOrigins = parseOrigins(process.env.CORS_ALLOWED_ORIGINS);
const socketOrigins = parseOrigins(process.env.SOCKET_ALLOWED_ORIGINS);
const corsAllowAll = httpOrigins.length === 0;
const effectiveSocketOrigins = socketOrigins.length ? socketOrigins : httpOrigins;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (!effectiveSocketOrigins.length || effectiveSocketOrigins.includes(origin)) {
        return callback(null, true);
      }
      console.warn(`Blocked Socket.IO origin: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  },
});

app.set('io', io);
app.set('trust proxy', 1);

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (corsAllowAll || httpOrigins.includes(origin)) return callback(null, true);
    console.warn(`Blocked CORS origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '1mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

const rateLimitWindowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX || '100', 10);
app.use(
  rateLimit({
    windowMs: rateLimitWindowMs,
    max: rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Routes
app.get('/', (req, res) => res.json({ ok: true, service: 'trade-advice-api', uptime: process.uptime() }));
app.get('/api/health', (req, res) => res.json({ ok: true }));
app.use('/api/auth', authRoutes);
app.use('/api/advice', adviceRoutes);
app.use('/api/wallet', walletRoutes);

app.use((err, req, res, next) => {
  if (err?.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS origin denied' });
  }
  console.error('Unhandled error', err);
  return res.status(500).json({ error: 'internal server error' });
});

// Socket.IO demo stream
io.on('connection', (socket) => {
  const categories = ['NIFTY', 'BANK_NIFTY', 'SENSEX', 'STOCK', 'COMMODITY'];
  const timer = setInterval(() => {
    const category = categories[Math.floor(Math.random() * categories.length)];
    const value = Math.round((Math.random() * 1000 + 100) * 100) / 100;
    socket.emit('market:tick', { category, value, ts: Date.now() });
  }, 1500);

  socket.on('disconnect', () => clearInterval(timer));
});

const PORT = parseInt(process.env.PORT || '4000', 10);
const HOST = process.env.HOST || '0.0.0.0';

connectDB()
  .then(() => {
    server.listen(PORT, HOST, () => console.log(`Server listening on http://${HOST}:${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to connect DB', err);
    process.exit(1);
  });

function gracefulShutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  server.close((serverErr) => {
    if (serverErr) {
      console.error('Error closing HTTP server', serverErr);
      process.exit(1);
    }
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed. Bye!');
      process.exit(0);
    });
  });
}

['SIGTERM', 'SIGINT'].forEach((signal) => {
  process.on(signal, () => gracefulShutdown(signal));
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled promise rejection', err);
});
