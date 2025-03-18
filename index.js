require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const { JWT_SECRET_KEY } = process.env;

const app = express();

const ALLOWED_IPS = new Set(["10.100.14.2", "104.28.245.127", "104.28.213.128", "104.28.213.124"]);

app.use(morgan(function (tokens, req, res) {
    return [
      tokens.method(req, res),
      tokens.url(req, res),
      tokens.status(req, res),
      tokens.res(req, res, 'content-length'), '-',
      tokens['response-time'](req, res), 'ms'
    ].join(' ')
}));
app.use(express.json());
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    const sanitizedIp = clientIp.includes('::ffff:') ? clientIp.split('::ffff:')[1] : clientIp;

    console.log(`INFO: Incoming request from IP: ${sanitizedIp}`);

    if (!ALLOWED_IPS.has(sanitizedIp)) {
        console.log(`WARNING: Unauthorized access attempt from ${sanitizedIp}`);
        return res.status(401).json({ error: "Forbidden", message: "Access denied" });
    }

    next();
});

app.get('/', (req, res) => {
    const ip_addr = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    return res.status(200).json({
        status: 'OK',
        message: `Welcome to Auth JWT Webhook for Hasura! Your IP address is ${ip_addr}`,
    });
});

app.get('/validate-request', (req, res) => {
    let authHeader = req.header('Authorization');
    
    if (!authHeader) {
        console.log('INFO: No Authorization header found. Granting anonymous access.');
        
        return res.status(200).json({
            'X-Hasura-Role': 'anonymous',
        });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        console.log('INFO: No token provided. Unauthorized.');

        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Missing token',
        });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET_KEY);

        if (!payload["claims.jwt.hasura.io"]) {
            console.log('INFO: Invalid payload structure. Unauthorized.');

            return res.status(403).json({
                error: 'Unauthorized',
                message: 'Invalid payload structure',
            });
        }

        const claims = payload["claims.jwt.hasura.io"];
            
        const sessionVariables = {
            'X-Hasura-User-Id': claims["x-hasura-user-id"] || payload.id,
            // 'X-Hasura-Role': claims["x-hasura-role"] || "user",
            'X-Hasura-Role': "admin",
        };

        return res.status(200).json(sessionVariables);
    } catch (error) {
        console.log('INFO: Invalid or expired token. Unauthorized.');

        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Invalid or expired token',
        });
    }
});

module.exports = app;