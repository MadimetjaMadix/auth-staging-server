require('dotenv').config();
const express = require('express');
const cors = require('cors');
const winston = require('winston');
const fs = require('fs').promises;
const path = require('path');
const authRoutes = require('./routes/auth');
const { apiKeyMiddleware } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Defined endpoints to log (exclude /logs, /logs-data, /config, /clear-logs)
const validEndpoints = [
    '/basic-auth',
    '/oauth2/token',
    '/oauth2-auth',
    '/api-key-auth',
    '/no-auth'
];

// Logger (write to /tmp for Vercel)
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: '/tmp/error.log', level: 'error' }),
        new winston.transports.File({ filename: '/tmp/combined.log' })
    ]
});

// Middleware to log only defined endpoint attempts
app.use((req, res, next) => {
    if (!validEndpoints.includes(req.originalUrl)) {
        return next();
    }
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        let logBody = req.body ? { ...req.body } : {};
        if (logBody.grant_type) logBody.grant_type = '[REDACTED]';
        if (logBody.password) logBody.password = '[REDACTED]';
        if (logBody.client_secret) logBody.client_secret = '[REDACTED]';
        const logEntry = {
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            headers: {
                ...req.headers,
                authorization: '[REDACTED]',
                [process.env.API_KEY_HEADER?.toLowerCase() || 'x-api-key']: '[REDACTED]'
            },
            body: logBody,
            duration: `${duration}ms`
        };
        if (res.statusCode >= 400) {
            logger.error('Endpoint attempt failed', logEntry);
        } else {
            logger.info('Endpoint attempt', logEntry);
        }
    });
    next();
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));
app.use('/', authRoutes);

// /config endpoint to provide BASE_URL
app.get('/config', (req, res) => {
    res.json({
        status: 'success',
        baseUrl: process.env.BASE_URL || 'https://auth-staging-server.vercel.app',
        timestamp: new Date().toISOString()
    });
});

// /logs endpoint (GET, serves HTML dashboard)
app.get('/logs', async (req, res) => {
    try {
        const dashboardPath = path.join(__dirname, '../public/logs-dashboard.html');
        const htmlContent = await fs.readFile(dashboardPath, 'utf8');
        res.set('Content-Type', 'text/html');
        res.send(htmlContent);
    } catch (err) {
        console.error('Error serving dashboard:', err.message);
        res.status(500).send('Error loading logs dashboard');
    }
});

// /logs-data endpoint (GET, serves JSON logs)
app.get('/logs-data', async (req, res) => {
    try {
        const logFile = '/tmp/combined.log';
        let logs = [];
        try {
            const data = await fs.readFile(logFile, 'utf8');
            logs = data
                .split('\n')
                .filter(line => line.trim())
                .map(line => {
                    try {
                        return JSON.parse(line);
                    } catch {
                        return null;
                    }
                })
                .filter(log => log && log.timestamp && log.method && log.url && validEndpoints.includes(log.url))
                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        } catch (err) {
            if (err.code === 'ENOENT') {
                logs = [];
            } else {
                throw err;
            }
        }
        res.json({
            status: 'success',
            logs,
            message: 'Logs retrieved successfully',
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('Error reading logs:', err.message);
        res.status(500).json({
            status: 'error',
            message: 'Failed to retrieve logs',
            errorCode: 'SERVER_ERROR'
        });
    }
});

// /clear-logs endpoint (POST, requires API key)
app.post('/clear-logs', apiKeyMiddleware, async (req, res) => {
    try {
        const logFiles = ['/tmp/combined.log', '/tmp/error.log'];
        for (const file of logFiles) {
            try {
                await fs.writeFile(file, ''); // Clear file contents instead of deleting
            } catch (err) {
                if (err.code !== 'ENOENT') {
                    throw err;
                }
            }
        }
        res.json({
            status: 'success',
            message: 'Logs cleared successfully',
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('Error clearing logs:', err.message);
        res.status(500).json({
            status: 'error',
            message: 'Failed to clear logs',
            errorCode: 'SERVER_ERROR'
        });
    }
});

// Reject non-GET for /logs, non-POST for /clear-logs
app.all('/logs', (req, res) => {
    res.status(405).json({
        status: 'error',
        message: 'Method Not Allowed, use GET',
        errorCode: 'METHOD_NOT_ALLOWED'
    });
});

app.all('/clear-logs', (req, res) => {
    res.status(405).json({
        status: 'error',
        message: 'Method Not Allowed, use POST',
        errorCode: 'METHOD_NOT_ALLOWED'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.message);
    res.status(500).json({ status: 'error', message: 'Internal server error', errorCode: 'SERVER_ERROR' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});