require('dotenv').config();
const express = require('express');
const cors = require('cors');
const winston = require('winston');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' })
    ]
});
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console());
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/logs', express.static('logs')); // Access logs via /logs
app.use('/', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error(err.message);
    res.status(500).json({ status: 'error', message: 'Internal server error', errorCode: 'SERVER_ERROR' });
});

app.listen(PORT, () => {
    logger.info(`Server running on http://localhost:${PORT}`);
});