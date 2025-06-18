const jwt = require('jsonwebtoken');
const User = require('../databasemodels/usermodel');

const authenticateToken = async (req, res, next) => {
    try {
        let token;

        // Check for token in different places
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies && req.cookies.token) {
            token = req.cookies.token;
        }

        if (!token) {
            return res.status(401).json({ 
                success: false,
                message: 'Access token required. Please login to continue.' 
            });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Get user from database to ensure they still exist
            const user = await User.findById(decoded.id).select('-password');
            
            if (!user) {
                return res.status(401).json({ 
                    success: false,
                    message: 'User not found. Please login again.' 
                });
            }

            // Update last seen and online status
            await User.findByIdAndUpdate(decoded.id, {
                lastSeen: new Date(),
                isOnline: true
            });

            // Attach user info to request
            req.user = {
                id: user._id,
                userId: user._id, // For backward compatibility
                username: user.username,
                email: user.email,
                phoneNumber: user.phoneNumber
            };

            next();
        } catch (jwtError) {
            console.error('JWT verification error:', jwtError);
            return res.status(403).json({ 
                success: false,
                message: 'Invalid or expired token. Please login again.' 
            });
        }

    } catch (error) {
        console.error('Authentication middleware error:', error);
        return res.status(500).json({ 
            success: false,
            message: 'Authentication failed' 
        });
    }
};

// Optional auth - doesn't fail if no token
const optionalAuth = async (req, res, next) => {
    try {
        let token;

        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies && req.cookies.token) {
            token = req.cookies.token;
        }

        if (token) {
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                const user = await User.findById(decoded.id).select('-password');
                
                if (user) {
                    req.user = {
                        id: user._id,
                        userId: user._id,
                        username: user.username,
                        email: user.email,
                        phoneNumber: user.phoneNumber
                    };
                }
            } catch (jwtError) {
                // Token invalid, but continue without user
                console.log('Optional auth: Invalid token');
            }
        }

        next();
    } catch (error) {
        console.error('Optional auth error:', error);
        next();
    }
};

module.exports = { 
    authenticateToken, 
    optionalAuth 
};