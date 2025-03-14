require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { JWT_SECRET_KEY } = process.env;

const app = express();

app.use(morgan('dev'));
app.use(express.json());
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    const ip_addr = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    return res.status(200).json({
        status: 'OK',
        message: `Welcome to Auth JWT Webhook for Hasura! Your IP address is ${ip_addr}`,
    });
});

app.post('/validate-request', (req, res) => {
    let authHeader = req.header('Authorization');
    if (!authHeader) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Missing Authorization header',
        });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Missing token',
        });
    }

    try {
        const payload = jwt.verify(token, SECRET_KEY);

        if (!payload["claims.jwt.hasura.io"]) {
            return res.status(403).json({
                error: 'Unauthorized',
                message: 'Invalid payload structure',
            });
        }

        const claims = payload["claims.jwt.hasura.io"];
            
        const sessionVariables = {
            'X-Hasura-User-Id': claims["x-hasura-user-id"] || payload.id,
            'X-Hasura-Role': claims["x-hasura-role"] || "user",
        };

        return res.status(200).json({ sessionVariables });
    } catch (error) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Invalid or expired token',
        });
    }
});

module.exports = app;