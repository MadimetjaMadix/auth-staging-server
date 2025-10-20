const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;
const JwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');

// In-memory "DB" (replace with MongoDB/PostgreSQL for prod-like staging)
const users = {
    'username': { password: 'password' } // Use bcrypt in prod
};
const clients = {
    'client_id': { secret: 'client_secret' }
};
const apiKeys = {
    'mock-api-key': true
};

// Basic Auth for /basic-auth and /oauth2/token
passport.use(new BasicStrategy((username, password, done) => {
    const user = users[username] || clients[username];
    if (user && user.password === password || user.secret === password) {
        return done(null, { username });
    }
    return done(null, false);
}));

// JWT for /oauth2-auth
passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
}, (payload, done) => {
    if (payload.client_id) {
        return done(null, payload);
    }
    return done(null, false);
}));

// Middleware for Basic Auth with header check
const basicAuthMiddleware = (req, res, next) => {
    if (!req.headers.authorization) {
        return res.status(401).json({
            status: 'error',
            message: 'Missing Authorization header for Basic Authentication',
            errorCode: 'AUTH_MISSING_HEADER'
        });
    }
    passport.authenticate('basic', { session: false }, (err, user) => {
        if (err || !user) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid or missing Basic Authentication credentials',
                errorCode: 'AUTH_INVALID_CREDENTIALS'
            });
        }
        req.user = user;
        next();
    })(req, res, next);
};

// Middleware for API Key
const apiKeyMiddleware = (req, res, next) => {
    const key = req.headers[process.env.API_KEY_HEADER?.toLowerCase() || 'x-api-key'];
    if (!key) {
        return res.status(401).json({
            status: 'error',
            message: 'Missing API Key header',
            errorCode: 'AUTH_MISSING_HEADER'
        });
    }
    if (!apiKeys[key]) {
        return res.status(401).json({
            status: 'error',
            message: 'Invalid API Key',
            errorCode: 'AUTH_INVALID_API_KEY'
        });
    }
    next();
};

// Middleware for OAuth2 Bearer Token
const oauth2Middleware = passport.authenticate('jwt', { session: false });

module.exports = { basicAuthMiddleware, apiKeyMiddleware, oauth2Middleware };