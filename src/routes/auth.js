const express = require('express');
const jwt = require('jsonwebtoken');
const { basicAuthMiddleware, apiKeyMiddleware, oauth2Middleware } = require('../middleware/auth');

const router = express.Router();

// Helper for consistent responses
const successResponse = (authType, message) => ({
    status: 'success',
    authType,
    message,
    timestamp: new Date().toISOString()
});

// OAuth2 Token Endpoint
router.post('/oauth2/token', basicAuthMiddleware, (req, res) => {
    const { grant_type } = req.body;
    if (grant_type !== 'client_credentials') {
        return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Grant type must be client_credentials' });
    }
    const token = jwt.sign({ client_id: req.user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({
        access_token: token,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'api_access',
        timestamp: new Date().toISOString()
    });
});

// Basic Auth Endpoint
router.post('/basic-auth', basicAuthMiddleware, (req, res) => {
    res.json(successResponse('BASIC', 'Authenticated successfully using Basic Auth'));
});

// OAuth2 Auth Endpoint
router.post('/oauth2-auth', oauth2Middleware, (req, res) => {
    if (!req.headers.authorization) {
        return res.status(401).json({
            status: 'error',
            message: 'Missing Authorization header for OAuth2 Bearer token',
            errorCode: 'AUTH_MISSING_HEADER'
        });
    }
    res.json(successResponse('OAUTH2', 'Authenticated successfully using OAuth2 Bearer token'));
});

// API Key Endpoint
router.post('/api-key-auth', apiKeyMiddleware, (req, res) => {
    res.json(successResponse('API_KEY', 'Authenticated successfully using API Key'));
});

// No Auth Endpoint
router.post('/no-auth', (req, res) => {
    res.json(successResponse('NONE', 'Access granted without authentication'));
});

module.exports = router;