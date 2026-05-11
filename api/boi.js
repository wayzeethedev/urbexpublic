import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v2 as cloudinary } from 'cloudinary';
import formidable from 'formidable-serverless';
import fs from 'fs';

// ==================== CONFIGURATION ====================
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Disable body parser for file upload endpoints
export const config = {
    api: {
        bodyParser: false,
    },
};

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const INVITES_COL = 'invite_requests';
const COMMENTS_COL = 'comments';
const USERS_COL = 'users';
const LOCATIONS_COL = 'locations';

let cachedClient = null;

async function getClient() {
    if (cachedClient) return cachedClient;
    if (!uri) throw new Error('MONGODB_URI is not defined');
    const client = new MongoClient(uri);
    await client.connect();
    cachedClient = client;
    return client;
}

// ==================== HELPER FUNCTIONS ====================
function isAdmin(req) {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return false;
    
    const cookies = {};
    cookieHeader.split(';').forEach(cookie => {
        const [key, value] = cookie.trim().split('=');
        cookies[key] = value;
    });
    
    const token = cookies.auth_token;
    if (!token) return false;
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const adminEmails = (process.env.ADMIN_EMAILS || '').split(',');
        return adminEmails.includes(decoded.email);
    } catch {
        return false;
    }
}

function getUserIdFromCookie(req) {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return null;
    
    const cookies = {};
    cookieHeader.split(';').forEach(cookie => {
        const [key, value] = cookie.trim().split('=');
        cookies[key] = value;
    });
    
    const token = cookies.auth_token;
    if (!token) return null;
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        return decoded.userId;
    } catch {
        return null;
    }
}

function getAdminInfo(req) {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return null;
    
    const cookies = {};
    cookieHeader.split(';').forEach(cookie => {
        const [key, value] = cookie.trim().split('=');
        cookies[key] = value;
    });
    
    const token = cookies.auth_token;
    if (!token) return null;
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const adminEmails = (process.env.ADMIN_EMAILS || '').split(',');
        if (adminEmails.includes(decoded.email)) {
            return { userId: decoded.userId, email: decoded.email };
        }
        return null;
    } catch {
        return null;
    }
}

function generateAccessToken() {
    return Math.floor(100000000000 + Math.random() * 900000000000).toString();
}

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 3959; // miles
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}

function setCorsHeaders(res) {
    const allowedOrigin = process.env.ALLOWED_ORIGINS || 'http://localhost:3000';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// ==================== MAIN HANDLER ====================
export default async function handler(req, res) {
    const url = req.url;
    const method = req.method;
    
    // Parse body for non-file uploads
    if (method !== 'OPTIONS' && !url.includes('upload')) {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        await new Promise(resolve => req.on('end', resolve));
        try {
            req.body = body ? JSON.parse(body) : {};
        } catch (e) {
            req.body = {};
        }
    }
    
    // Helper to set method-specific headers
    const setMethodHeaders = (methods) => {
        setCorsHeaders(res);
        res.setHeader('Access-Control-Allow-Methods', `${methods.join(', ')}, OPTIONS`);
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        if (method === 'OPTIONS') {
            res.status(200).end();
            return true;
        }
        return false;
    };
    
    // ==================== AUTH ENDPOINTS ====================
    if (url === '/api/auth/check' || url === '/check-auth') {
        if (setMethodHeaders(['GET'])) return;
        
        const cookieHeader = req.headers.cookie;
        if (!cookieHeader) {
            return res.status(401).json({ error: 'Not authenticated', authenticated: false });
        }
        
        const cookies = {};
        cookieHeader.split(';').forEach(cookie => {
            const [key, value] = cookie.trim().split('=');
            cookies[key] = value;
        });
        
        const token = cookies.auth_token;
        if (!token) {
            return res.status(401).json({ error: 'Not authenticated', authenticated: false });
        }
        
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            const user = await usersCol.findOne({ _id: new ObjectId(decoded.userId) });
            
            if (!user) {
                return res.status(401).json({ error: 'User not found', authenticated: false });
            }
            
            return res.status(200).json({
                authenticated: true,
                user: {
                    userId: user._id.toString(),
                    username: user.username,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    displayName: user.displayName
                }
            });
        } catch (err) {
            return res.status(401).json({ error: 'Invalid or expired token', authenticated: false });
        }
    }
    
    if (url === '/api/auth/login' || url === '/login') {
        if (setMethodHeaders(['POST'])) return;
        
        const { identifier, password } = req.body;
        if (!identifier || !password) {
            return res.status(400).json({ error: 'Username/Email and password are required.' });
        }
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const user = await usersCol.findOne({
                $or: [
                    { username: identifier.toLowerCase() },
                    { email: identifier.toLowerCase() }
                ]
            });
            
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials.' });
            }
            
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials.' });
            }
            
            await usersCol.updateOne({ _id: user._id }, { $set: { lastLogin: new Date() } });
            
            const token = jwt.sign({
                userId: user._id.toString(),
                username: user.username,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName
            }, process.env.JWT_SECRET, { expiresIn: '7d' });
            
            res.setHeader('Set-Cookie', `auth_token=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=604800; Path=/`);
            return res.status(200).json({
                ok: true,
                message: 'Login successful',
                user: {
                    username: user.username,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName
                }
            });
        } catch (err) {
            console.error('Login error:', err);
            return res.status(500).json({ error: 'Failed to login. Please try again.' });
        }
    }
    
    if (url === '/api/auth/logout' || url === '/logout') {
        if (setMethodHeaders(['POST'])) return;
        res.setHeader('Set-Cookie', 'auth_token=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/');
        return res.status(200).json({ ok: true, message: 'Logged out successfully' });
    }
    
    if (url === '/api/invite/request' || url === '/request') {
        if (setMethodHeaders(['POST'])) return;
        
        const { name, email, comments } = req.body ?? {};
        const nameParts = name.trim().split(' ');
        const firstName = nameParts[0];
        const lastName = nameParts.slice(1).join(' ') || '';
        
        if (!firstName || firstName.trim().length === 0) {
            return res.status(400).json({ error: 'First name is required.' });
        }
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'A valid email address is required.' });
        }
        
        try {
            const client = await getClient();
            const col = client.db(DB).collection(INVITES_COL);
            
            const existing = await col.findOne({ email: email.toLowerCase().trim() });
            if (existing) {
                return res.status(409).json({ error: 'A request from this email already exists.' });
            }
            
            let accessToken;
            let isUnique = false;
            while (!isUnique) {
                accessToken = generateAccessToken();
                const existingToken = await col.findOne({ accessToken: accessToken });
                if (!existingToken) isUnique = true;
            }
            
            await col.insertOne({
                firstName: firstName.trim(),
                lastName: lastName.trim(),
                email: email.toLowerCase().trim(),
                comments: comments?.trim() ?? '',
                status: 'pending',
                accessToken: accessToken,
                createdAt: new Date(),
            });
            
            return res.status(200).json({
                ok: true,
                message: 'Request submitted successfully. You will be notified when approved.',
            });
        } catch (err) {
            console.error('MongoDB error:', err);
            return res.status(500).json({ error: 'Failed to save your request. Please try again.' });
        }
    }
    
    if (url === '/api/invite/verify-token' || url === '/verify-token') {
        if (setMethodHeaders(['POST'])) return;
        
        const { token } = req.body;
        if (!token || !/^\d{12}$/.test(token)) {
            return res.status(400).json({ error: 'Valid 12-digit access token is required.' });
        }
        
        try {
            const client = await getClient();
            const col = client.db(DB).collection(INVITES_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            
            const request = await col.findOne({ accessToken: token });
            if (!request) {
                return res.status(401).json({ error: 'Invalid access token.' });
            }
            
            const existingUser = await usersCol.findOne({ email: request.email });
            if (existingUser) {
                return res.status(409).json({ error: 'This access token has already been used.' });
            }
            
            return res.status(200).json({
                ok: true,
                firstName: request.firstName,
                lastName: request.lastName,
                email: request.email,
                token: token
            });
        } catch (err) {
            console.error('Token verification error:', err);
            return res.status(500).json({ error: 'Failed to verify access token.' });
        }
    }
    
    if (url === '/api/auth/register' || url === '/register') {
        if (setMethodHeaders(['POST'])) return;
        
        const { token, username, password, acceptedTerms } = req.body;
        
        if (!token || !/^\d{12}$/.test(token)) {
            return res.status(400).json({ error: 'Valid access token is required.' });
        }
        if (!username || username.length < 3 || username.length > 30) {
            return res.status(400).json({ error: 'Username must be 3-30 characters.' });
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores.' });
        }
        if (!password || password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters.' });
        }
        if (!acceptedTerms) {
            return res.status(400).json({ error: 'You must accept the terms and policies.' });
        }
        
        try {
            const client = await getClient();
            const requestsCol = client.db(DB).collection(INVITES_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            
            const request = await requestsCol.findOne({
                accessToken: token,
                registeredAt: { $exists: false }
            });
            
            if (!request) {
                return res.status(401).json({ error: 'Invalid or already used access token.' });
            }
            
            const existingUsername = await usersCol.findOne({ username: username.toLowerCase() });
            if (existingUsername) {
                return res.status(409).json({ error: 'Username already taken. Please choose another.' });
            }
            
            const existingEmail = await usersCol.findOne({ email: request.email });
            if (existingEmail) {
                return res.status(409).json({ error: 'This email has already been registered.' });
            }
            
            const hashedPassword = await bcrypt.hash(password, 10);
            
            await usersCol.insertOne({
                username: username.toLowerCase(),
                email: request.email,
                firstName: request.firstName,
                lastName: request.lastName,
                password: hashedPassword,
                accessToken: token,
                createdAt: new Date(),
                lastLogin: null,
                points: 0,
                earnedLocationIds: [],
                unclaimedLocationIds: [],
                visitedLocationIds: [],
                contributedLocations: [],
                hasReceivedWelcomeLocations: false,
                dailyLocationsClaimed: 0,
                redeemedLocations: 0
            });
            
            await requestsCol.updateOne({ accessToken: token }, { $set: { registeredAt: new Date() } });
            
            return res.status(200).json({
                ok: true,
                message: 'Registration successful! You can now login.'
            });
        } catch (err) {
            console.error('Registration error:', err);
            return res.status(500).json({ error: 'Failed to complete registration.' });
        }
    }
    
    // ==================== ADMIN INVITE ENDPOINTS ====================
    if (url === '/api/admin-invites' || url === '/invites') {
        if (setMethodHeaders(['GET'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        try {
            const client = await getClient();
            const invitesCol = client.db(DB).collection(INVITES_COL);
            const invites = await invitesCol.find({ status: 'pending' }).sort({ createdAt: -1 }).toArray();
            return res.status(200).json({ invites: invites });
        } catch (err) {
            console.error('Get invites error:', err);
            return res.status(500).json({ error: 'Failed to get invites' });
        }
    }
    
    if (url === '/api/admin-approve-invite' || url === '/approve') {
        if (setMethodHeaders(['POST'])) return;
        
        const adminKey = req.headers['x-admin-key'];
        if (adminKey !== process.env.ADMIN_SECRET_KEY) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required' });
        
        try {
            const client = await getClient();
            const col = client.db(DB).collection(INVITES_COL);
            const accessToken = generateAccessToken();
            
            const result = await col.updateOne(
                { email: email.toLowerCase().trim(), status: 'pending' },
                { $set: { status: 'approved', accessToken: accessToken, approvedAt: new Date() } }
            );
            
            if (result.matchedCount === 0) {
                return res.status(404).json({ error: 'Pending request not found' });
            }
            
            return res.status(200).json({
                ok: true,
                accessToken: accessToken,
                message: `User approved. Send this access token to ${email}: ${accessToken}`
            });
        } catch (err) {
            console.error('Approval error:', err);
            return res.status(500).json({ error: 'Failed to approve request' });
        }
    }
    
    if (url === '/api/admin-accept-invite' || url === '/accept-invite') {
        if (setMethodHeaders(['POST'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        const { inviteId } = req.body;
        if (!inviteId) return res.status(400).json({ error: 'Invite ID required' });
        
        try {
            const client = await getClient();
            const invitesCol = client.db(DB).collection(INVITES_COL);
            const { ObjectId } = await import('mongodb');
            
            const result = await invitesCol.updateOne({ _id: new ObjectId(inviteId) }, { $set: { status: 'approved' } });
            if (result.matchedCount === 0) return res.status(404).json({ error: 'Invite not found' });
            return res.status(200).json({ success: true, message: 'Invite accepted' });
        } catch (err) {
            console.error('Accept invite error:', err);
            return res.status(500).json({ error: 'Failed to accept invite' });
        }
    }
    
    if (url === '/api/admin-deny-invite' || url === '/deny-invite') {
        if (setMethodHeaders(['POST'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        const { inviteId } = req.body;
        if (!inviteId) return res.status(400).json({ error: 'Invite ID required' });
        
        try {
            const client = await getClient();
            const invitesCol = client.db(DB).collection(INVITES_COL);
            const { ObjectId } = await import('mongodb');
            
            const result = await invitesCol.updateOne({ _id: new ObjectId(inviteId) }, { $set: { status: 'denied' } });
            if (result.matchedCount === 0) return res.status(404).json({ error: 'Invite not found' });
            return res.status(200).json({ success: true, message: 'Invite denied' });
        } catch (err) {
            console.error('Deny invite error:', err);
            return res.status(500).json({ error: 'Failed to deny invite' });
        }
    }
    
    // ==================== ADMIN USER ENDPOINTS ====================
    if (url === '/api/admin-users' || url === '/users') {
        if (setMethodHeaders(['GET'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const users = await usersCol.find({}).sort({ createdAt: -1 }).toArray();
            const safeUsers = users.map(user => {
                const { password, ...safeUser } = user;
                return safeUser;
            });
            return res.status(200).json({ users: safeUsers });
        } catch (err) {
            console.error('Get users error:', err);
            return res.status(500).json({ error: 'Failed to get users' });
        }
    }
    
    if (url === '/api/admin-update-user' || url === '/update-user') {
        if (setMethodHeaders(['POST'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        const { userId, username, firstName, lastName, email, points } = req.body;
        if (!userId) return res.status(400).json({ error: 'User ID required' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const updateData = {};
            if (username !== undefined) updateData.username = username;
            if (firstName !== undefined) updateData.firstName = firstName;
            if (lastName !== undefined) updateData.lastName = lastName;
            if (email !== undefined) updateData.email = email;
            if (points !== undefined) updateData.points = points;
            
            const result = await usersCol.updateOne({ _id: new ObjectId(userId) }, { $set: updateData });
            if (result.matchedCount === 0) return res.status(404).json({ error: 'User not found' });
            return res.status(200).json({ success: true, message: 'User updated' });
        } catch (err) {
            console.error('Update user error:', err);
            return res.status(500).json({ error: 'Failed to update user' });
        }
    }
    
    // ==================== ADMIN LOCATION ENDPOINTS ====================
    if (url === '/api/admin/locations/pending' || url === '/pending') {
        if (setMethodHeaders(['GET'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        try {
            const client = await getClient();
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            
            const pendingLocations = await locationsCol.find({ status: 'pending' }).sort({ createdAt: -1 }).toArray();
            const locationsWithUser = await Promise.all(pendingLocations.map(async (loc) => {
                const user = await usersCol.findOne({ _id: loc.createdBy });
                return {
                    ...loc,
                    user: user ? {
                        username: user.username,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        email: user.email
                    } : null
                };
            }));
            return res.status(200).json({ success: true, locations: locationsWithUser });
        } catch (err) {
            console.error('Get pending locations error:', err);
            return res.status(500).json({ error: 'Failed to get pending locations' });
        }
    }
    
    if (url === '/api/admin/locations/approved' || url === '/approved') {
        if (setMethodHeaders(['GET'])) return;
        
        try {
            const client = await getClient();
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            
            const locations = await locationsCol.find({ status: 'approved' }).sort({ createdAt: -1 }).toArray();
            const locationsWithSubmitters = await Promise.all(locations.map(async (location) => {
                let submitterUsername = 'unknown';
                if (location.createdBy) {
                    const submitter = await usersCol.findOne({ _id: location.createdBy });
                    if (submitter) submitterUsername = submitter.username;
                }
                return { ...location, submitterUsername };
            }));
            return res.status(200).json({ success: true, locations: locationsWithSubmitters });
        } catch (err) {
            console.error('Get approved locations error:', err);
            return res.status(500).json({ error: 'Failed to get locations' });
        }
    }
    
    if (url === '/api/admin/locations/approve' || url === '/locations/approve') {
        if (setMethodHeaders(['POST'])) return;
        
        const admin = getAdminInfo(req);
        if (!admin) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        const { locationId, action, points, deniedReason } = req.body;
        if (!locationId) return res.status(400).json({ error: 'Location ID is required' });
        if (action !== 'approve' && action !== 'deny') return res.status(400).json({ error: 'Action must be approve or deny' });
        
        try {
            const client = await getClient();
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const location = await locationsCol.findOne({ _id: new ObjectId(locationId) });
            if (!location) return res.status(404).json({ error: 'Location not found' });
            if (location.status !== 'pending') return res.status(400).json({ error: 'Location already processed' });
            
            if (action === 'approve') {
                if (!points || points < 2 || points > 20) {
                    return res.status(400).json({ error: 'Points must be between 2 and 20' });
                }
                
                const creatorId = location.createdBy.toString();
                const visitorIds = [creatorId];
                
                await locationsCol.updateOne({ _id: new ObjectId(locationId) }, {
                    $set: {
                        status: 'approved',
                        points: points,
                        visitorCount: 1,
                        visitorIds: visitorIds,
                        approvedBy: new ObjectId(admin.userId),
                        approvedAt: new Date()
                    }
                });
                
                await usersCol.updateOne({ _id: location.createdBy }, {
                    $inc: { points: points },
                    $addToSet: { earnedLocationIds: locationId, visitedLocationIds: locationId },
                    $push: { contributedLocations: {
                        locationId: new ObjectId(locationId),
                        title: location.title,
                        points: points,
                        approvedAt: new Date()
                    }}
                });
                
                return res.status(200).json({ success: true, message: `Location approved! User earned ${points} points and automatically unlocked this location.` });
            } else {
                await locationsCol.updateOne({ _id: new ObjectId(locationId) }, {
                    $set: {
                        status: 'denied',
                        deniedReason: deniedReason || 'No reason provided',
                        approvedBy: new ObjectId(admin.userId),
                        approvedAt: new Date()
                    }
                });
                return res.status(200).json({ success: true, message: 'Location denied' });
            }
        } catch (err) {
            console.error('Approve/deny error:', err);
            return res.status(500).json({ error: 'Failed to process location: ' + err.message });
        }
    }
    
    // ==================== ADMIN COMMENT ENDPOINTS ====================
    if (url === '/api/admin-comments' || url === '/admin/comments') {
        if (setMethodHeaders(['GET'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        try {
            const client = await getClient();
            const commentsCol = client.db(DB).collection(COMMENTS_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            
            const comments = await commentsCol.find({}).sort({ createdAt: -1 }).toArray();
            const commentsWithInfo = await Promise.all(comments.map(async (comment) => {
                let username = 'Unknown';
                let locationTitle = 'Unknown';
                
                if (comment.userId) {
                    const user = await usersCol.findOne({ _id: comment.userId });
                    if (user) username = user.username;
                }
                if (comment.locationId) {
                    const location = await locationsCol.findOne({ _id: comment.locationId });
                    if (location) locationTitle = location.title;
                }
                return {
                    _id: comment._id.toString(),
                    username: username,
                    locationTitle: locationTitle,
                    text: comment.text,
                    createdAt: comment.createdAt,
                    upvotes: comment.votes?.filter(v => v.type === 'up').length || 0,
                    downvotes: comment.votes?.filter(v => v.type === 'down').length || 0
                };
            }));
            return res.status(200).json({ comments: commentsWithInfo });
        } catch (err) {
            console.error('Get comments error:', err);
            return res.status(500).json({ error: 'Failed to get comments' });
        }
    }
    
    if (url === '/api/admin-delete-comment' || url === '/delete-comment') {
        if (setMethodHeaders(['DELETE'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        const { commentId } = req.body;
        if (!commentId) return res.status(400).json({ error: 'Comment ID required' });
        
        try {
            const client = await getClient();
            const commentsCol = client.db(DB).collection(COMMENTS_COL);
            const { ObjectId } = await import('mongodb');
            
            const result = await commentsCol.deleteOne({ _id: new ObjectId(commentId) });
            if (result.deletedCount === 0) return res.status(404).json({ error: 'Comment not found' });
            return res.status(200).json({ success: true, message: 'Comment deleted' });
        } catch (err) {
            console.error('Delete comment error:', err);
            return res.status(500).json({ error: 'Failed to delete comment' });
        }
    }
    
    // ==================== ADMIN GIFT ENDPOINTS ====================
    if (url === '/api/admin-gift-locations' || url === '/gift-locations') {
        if (setMethodHeaders(['POST'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        const { userId, locationIds } = req.body;
        if (!userId) return res.status(400).json({ error: 'User ID required' });
        if (!locationIds || !locationIds.length) return res.status(400).json({ error: 'Location IDs required' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const userIds = Array.isArray(userId) ? userId.map(id => new ObjectId(id)) : [new ObjectId(userId)];
            for (const uid of userIds) {
                await usersCol.updateOne({ _id: uid }, { $addToSet: { earnedLocationIds: { $each: locationIds } } });
            }
            const count = userIds.length;
            return res.status(200).json({ success: true, message: `Gifted ${locationIds.length} locations to ${count} user${count !== 1 ? 's' : ''}` });
        } catch (err) {
            console.error('Gift locations error:', err);
            return res.status(500).json({ error: 'Failed to gift locations' });
        }
    }
    
    if (url === '/api/admin-gift-nearest-locations' || url === '/gift-nearest-locations') {
        if (setMethodHeaders(['POST'])) return;
        if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden - Admin only' });
        
        const { userIds, count } = req.body;
        if (!userIds || !userIds.length) return res.status(400).json({ error: 'User IDs required' });
        if (!count || count < 1) return res.status(400).json({ error: 'Valid count required' });
        
        function getNearestUnlockedLocations(userLocation, allLocations, earnedIds, count) {
            const availableLocations = allLocations.filter(loc => !earnedIds.includes(loc._id.toString()));
            const locationsWithDistance = availableLocations.map(loc => ({
                ...loc,
                distance: calculateDistance(userLocation.lat, userLocation.lng, loc.coordinates.lat, loc.coordinates.lng)
            }));
            return locationsWithDistance.sort((a, b) => a.distance - b.distance).slice(0, count);
        }
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            const { ObjectId } = await import('mongodb');
            
            const allLocations = await locationsCol.find({ status: 'approved' }).toArray();
            let totalGifted = 0;
            
            for (const userId of userIds) {
                const user = await usersCol.findOne({ _id: new ObjectId(userId) });
                if (!user) continue;
                
                const earnedIds = user.earnedLocationIds || [];
                let userLocation = null;
                if (user.lastLocation) {
                    userLocation = user.lastLocation;
                } else if (user.unlockedLocations && user.unlockedLocations.length > 0) {
                    const firstLocation = allLocations.find(l => l._id.toString() === user.unlockedLocations[0]);
                    if (firstLocation) userLocation = firstLocation.coordinates;
                }
                if (!userLocation) {
                    userLocation = { lat: 44.8614, lng: -92.6238 };
                }
                
                const nearestLocations = getNearestUnlockedLocations(userLocation, allLocations, earnedIds, count);
                if (nearestLocations.length > 0) {
                    const locationIds = nearestLocations.map(loc => loc._id.toString());
                    await usersCol.updateOne({ _id: new ObjectId(userId) }, { $addToSet: { earnedLocationIds: { $each: locationIds } } });
                    totalGifted += locationIds.length;
                }
            }
            return res.status(200).json({ success: true, message: `Gifted ${totalGifted} locations to ${userIds.length} user${userIds.length !== 1 ? 's' : ''}` });
        } catch (err) {
            console.error('Gift nearest locations error:', err);
            return res.status(500).json({ error: 'Failed to gift locations' });
        }
    }
    
    // ==================== USER DASHBOARD ENDPOINTS ====================
    if (url === '/api/user-dashboard' || url === '/dashboard') {
        if (setMethodHeaders(['GET'])) return;
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            const { ObjectId } = await import('mongodb');
            
            const user = await usersCol.findOne({ _id: new ObjectId(userId) });
            if (!user) return res.status(404).json({ error: 'User not found' });
            
            const signupDate = new Date(user.signupDate || user.createdAt);
            const today = new Date();
            const daysSinceSignup = Math.floor((today - signupDate) / (1000 * 60 * 60 * 24));
            
            const earnedIds = user.earnedLocationIds || [];
            const earnedLocations = earnedIds.length > 0 ? await locationsCol.find({ _id: { $in: earnedIds.map(id => new ObjectId(id)) } }).toArray() : [];
            const unclaimedIds = user.unclaimedLocationIds || [];
            const unclaimedLocations = unclaimedIds.length > 0 ? await locationsCol.find({ _id: { $in: unclaimedIds.map(id => new ObjectId(id)) } }).toArray() : [];
            const visitedIds = user.visitedLocationIds || [];
            const contributedLocations = user.contributedLocations || [];
            
            const earnedWithSubmitters = await Promise.all(earnedLocations.map(async (loc) => {
                let submitterUsername = 'unknown';
                if (loc.createdBy) {
                    const submitter = await usersCol.findOne({ _id: loc.createdBy });
                    if (submitter) submitterUsername = submitter.username;
                }
                return { ...loc, submitterUsername };
            }));
            
            const unclaimedWithSubmitters = await Promise.all(unclaimedLocations.map(async (loc) => {
                let submitterUsername = 'unknown';
                if (loc.createdBy) {
                    const submitter = await usersCol.findOne({ _id: loc.createdBy });
                    if (submitter) submitterUsername = submitter.username;
                }
                return { ...loc, submitterUsername };
            }));
            
            return res.status(200).json({
                success: true,
                user: {
                    username: user.username,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    points: user.points || 0,
                    signupDate: signupDate,
                    daysSinceSignup: daysSinceSignup,
                    dailyLocationsClaimed: user.dailyLocationsClaimed || 0,
                    redeemedLocations: user.redeemedLocations || 0,
                    earnedLocationCount: earnedIds.length,
                    unclaimedLocationCount: unclaimedIds.length,
                    visitedLocationCount: visitedIds.length,
                    totalLocationsUnlocked: earnedIds.length + unclaimedIds.length,
                    hasReceivedWelcomeLocations: user.hasReceivedWelcomeLocations || false,
                    contributedLocations: contributedLocations
                },
                earnedLocations: earnedWithSubmitters,
                unclaimedLocations: unclaimedWithSubmitters,
                visitedLocationIds: visitedIds
            });
        } catch (err) {
            console.error('Dashboard error:', err);
            return res.status(500).json({ error: 'Failed to load dashboard' });
        }
    }
    
    // ==================== USER POINTS ENDPOINTS ====================
    if (url === '/api/user-points' || url === '/points') {
        if (setMethodHeaders(['GET'])) return;
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const user = await usersCol.findOne({ _id: new ObjectId(userId) });
            if (!user) return res.status(404).json({ error: 'User not found' });
            
            return res.status(200).json({ points: user.points || 0, hasInitialLocations: user.unlockedLocations && user.unlockedLocations.length > 0 });
        } catch (err) {
            console.error('Get points error:', err);
            return res.status(500).json({ error: 'Failed to get points' });
        }
    }
    
    // ==================== DAILY LOCATIONS ====================
    if (url === '/api/user-daily-locations' || url === '/daily-locations') {
        if (setMethodHeaders(['GET', 'POST'])) return;
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            const { ObjectId } = await import('mongodb');
            
            let user = await usersCol.findOne({ _id: new ObjectId(userId) });
            if (!user) return res.status(404).json({ error: 'User not found' });
            
            let userLat = null, userLng = null;
            if (req.body && req.body.latitude && req.body.longitude) {
                userLat = req.body.latitude;
                userLng = req.body.longitude;
            }
            
            let allLocations = await locationsCol.find({ status: 'approved' }).toArray();
            let welcomeLocationsAdded = 0;
            
            if (!user.hasReceivedWelcomeLocations) {
                if (userLat && userLng && allLocations.length > 0) {
                    const locationsWithDistance = allLocations.map(loc => ({
                        ...loc,
                        distance: calculateDistance(userLat, userLng, loc.coordinates.lat, loc.coordinates.lng)
                    }));
                    const nearest15 = locationsWithDistance.sort((a, b) => a.distance - b.distance).slice(0, 15);
                    const welcomeLocationIds = nearest15.map(loc => loc._id.toString());
                    
                    await usersCol.updateOne({ _id: new ObjectId(userId) }, {
                        $set: { hasReceivedWelcomeLocations: true },
                        $addToSet: { unclaimedLocationIds: { $each: welcomeLocationIds } }
                    });
                    welcomeLocationsAdded = welcomeLocationIds.length;
                    user = await usersCol.findOne({ _id: new ObjectId(userId) });
                } else {
                    await usersCol.updateOne({ _id: new ObjectId(userId) }, { $set: { hasReceivedWelcomeLocations: true } });
                }
            }
            
            const signupDate = new Date(user.signupDate || user.createdAt);
            const today = new Date();
            const daysSinceSignup = Math.floor((today - signupDate) / (1000 * 60 * 60 * 24));
            const dailyLocationsAvailable = Math.max(0, daysSinceSignup - (user.dailyLocationsClaimed || 0));
            const earnedLocationsAvailable = (user.points || 0) - (user.redeemedLocations || 0);
            
            const earnedIds = user.earnedLocationIds || [];
            const unclaimedIds = user.unclaimedLocationIds || [];
            const alreadyHaveIds = [...earnedIds, ...unclaimedIds];
            let availableLocations = allLocations.filter(loc => !alreadyHaveIds.includes(loc._id.toString()));
            
            if (userLat && userLng && availableLocations.length > 0) {
                availableLocations.forEach(loc => {
                    loc.distance = calculateDistance(userLat, userLng, loc.coordinates.lat, loc.coordinates.lng);
                });
                availableLocations.sort((a, b) => a.distance - b.distance);
            }
            
            const dailyLocationsToAdd = Math.min(dailyLocationsAvailable, availableLocations.length);
            const newDailyLocations = availableLocations.slice(0, dailyLocationsToAdd);
            const earnedLocationsToAdd = Math.min(earnedLocationsAvailable, availableLocations.length - dailyLocationsToAdd);
            const newEarnedLocations = availableLocations.slice(dailyLocationsToAdd, dailyLocationsToAdd + earnedLocationsToAdd);
            const allNewUnclaimed = [...newDailyLocations, ...newEarnedLocations];
            const newUnclaimedIds = allNewUnclaimed.map(loc => loc._id.toString());
            
            if (newUnclaimedIds.length > 0) {
                const updateData = { $addToSet: { unclaimedLocationIds: { $each: newUnclaimedIds } } };
                if (dailyLocationsToAdd > 0) updateData.$inc = { dailyLocationsClaimed: dailyLocationsToAdd };
                if (earnedLocationsToAdd > 0) updateData.$inc = { ...(updateData.$inc || {}), redeemedLocations: earnedLocationsToAdd };
                await usersCol.updateOne({ _id: new ObjectId(userId) }, updateData);
            }
            
            const totalNewUnlocked = welcomeLocationsAdded + newUnclaimedIds.length;
            
            return res.status(200).json({
                success: true,
                welcomeLocationsAdded: welcomeLocationsAdded,
                daysSinceSignup,
                dailyLocationsClaimed: user.dailyLocationsClaimed || 0,
                dailyLocationsAvailable: dailyLocationsAvailable,
                dailyLocationsAdded: dailyLocationsToAdd,
                earnedLocationsAvailable: earnedLocationsAvailable,
                earnedLocationsAdded: earnedLocationsToAdd,
                totalNewUnlocked: totalNewUnlocked,
                newUnclaimedIds: newUnclaimedIds,
                isWelcome: welcomeLocationsAdded > 0
            });
        } catch (err) {
            console.error('Daily locations error:', err);
            return res.status(500).json({ error: 'Failed to process daily locations' });
        }
    }
    
    // ==================== LOCATION CLAIM ENDPOINTS ====================
    if (url === '/api/locations/claim' || url === '/claim-location') {
        if (setMethodHeaders(['POST'])) return;
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        const { locationId } = req.body;
        if (!locationId) return res.status(400).json({ error: 'Location ID required' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const user = await usersCol.findOne({ _id: new ObjectId(userId) });
            if (!user) return res.status(404).json({ error: 'User not found' });
            
            const unclaimedIds = user.unclaimedLocationIds || [];
            if (!unclaimedIds.includes(locationId)) {
                return res.status(400).json({ error: 'Location not available to claim' });
            }
            
            await usersCol.updateOne({ _id: new ObjectId(userId) }, {
                $pull: { unclaimedLocationIds: locationId },
                $addToSet: { earnedLocationIds: locationId }
            });
            
            return res.status(200).json({ success: true, message: 'Location claimed successfully!' });
        } catch (err) {
            console.error('Claim location error:', err);
            return res.status(500).json({ error: 'Failed to claim location' });
        }
    }
    
    if (url === '/api/locations/claim-all' || url === '/claim-all') {
        if (setMethodHeaders(['POST'])) return;
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const user = await usersCol.findOne({ _id: new ObjectId(userId) });
            if (!user) return res.status(404).json({ error: 'User not found' });
            
            const unclaimedIds = user.unclaimedLocationIds || [];
            if (unclaimedIds.length === 0) {
                return res.status(200).json({ success: true, claimedCount: 0, message: 'No locations to claim' });
            }
            
            await usersCol.updateOne({ _id: new ObjectId(userId) }, {
                $pull: { unclaimedLocationIds: { $in: unclaimedIds } },
                $addToSet: { earnedLocationIds: { $each: unclaimedIds } }
            });
            
            return res.status(200).json({ success: true, claimedCount: unclaimedIds.length, message: `Claimed ${unclaimedIds.length} locations!` });
        } catch (err) {
            console.error('Claim all error:', err);
            return res.status(500).json({ error: 'Failed to claim locations' });
        }
    }
    
    // ==================== LOCATION VISIT ENDPOINTS ====================
    if (url === '/api/locations/visit' || url === '/visit-location') {
        if (setMethodHeaders(['POST'])) return;
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        const { locationId } = req.body;
        if (!locationId) return res.status(400).json({ error: 'Location ID required' });
        
        try {
            const client = await getClient();
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const user = await usersCol.findOne({ _id: new ObjectId(userId) });
            if (!user) return res.status(404).json({ error: 'User not found' });
            
            const location = await locationsCol.findOne({ _id: new ObjectId(locationId) });
            if (!location) return res.status(404).json({ error: 'Location not found' });
            
            const hasVisited = user.visitedLocationIds && user.visitedLocationIds.includes(locationId);
            
            if (!hasVisited) {
                await usersCol.updateOne({ _id: new ObjectId(userId) }, {
                    $addToSet: { visitedLocationIds: locationId, earnedLocationIds: locationId }
                });
                
                const visitorIds = location.visitorIds || [];
                if (!visitorIds.includes(userId)) {
                    visitorIds.push(userId);
                    await locationsCol.updateOne({ _id: new ObjectId(locationId) }, {
                        $set: { visitorCount: visitorIds.length, visitorIds: visitorIds }
                    });
                }
                return res.status(200).json({ success: true, message: 'Location marked as visited!', isConfirmed: location.visitorCount + 1 > 1 });
            }
            return res.status(200).json({ success: true, message: 'Already visited this location', isConfirmed: location.visitorCount > 1 });
        } catch (err) {
            console.error('Visit location error:', err);
            return res.status(500).json({ error: 'Failed to process visit' });
        }
    }
    
    // ==================== COMMENTS ENDPOINTS ====================
    if (url === '/api/comments' || url === '/comments') {
        if (method === 'OPTIONS') {
            setCorsHeaders(res);
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
            return res.status(200).end();
        }
        setCorsHeaders(res);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        
        if (method === 'GET') {
            const { locationId } = req.query;
            if (!locationId) return res.status(400).json({ error: 'Location ID required' });
            
            try {
                const client = await getClient();
                const commentsCol = client.db(DB).collection(COMMENTS_COL);
                const usersCol = client.db(DB).collection(USERS_COL);
                const { ObjectId } = await import('mongodb');
                
                const comments = await commentsCol.find({ locationId: new ObjectId(locationId) }).sort({ createdAt: -1 }).toArray();
                const userId = getUserIdFromCookie(req);
                
                const commentsWithUsernames = await Promise.all(comments.map(async (comment) => {
                    let username = 'Unknown';
                    if (comment.userId) {
                        const user = await usersCol.findOne({ _id: comment.userId });
                        if (user) username = user.username;
                    }
                    const userVote = comment.votes?.find(v => v.userId === userId);
                    return {
                        _id: comment._id.toString(),
                        username: username,
                        text: comment.text,
                        createdAt: comment.createdAt,
                        upvotes: comment.votes?.filter(v => v.type === 'up').length || 0,
                        downvotes: comment.votes?.filter(v => v.type === 'down').length || 0,
                        userVote: userVote?.type || null
                    };
                }));
                return res.status(200).json({ comments: commentsWithUsernames });
            } catch (err) {
                console.error('Get comments error:', err);
                return res.status(500).json({ error: 'Failed to get comments: ' + err.message });
            }
        }
        
        if (method === 'POST') {
            const userId = getUserIdFromCookie(req);
            if (!userId) return res.status(401).json({ error: 'Not authenticated' });
            
            const { locationId, text } = req.body;
            if (!locationId || !text || !text.trim()) {
                return res.status(400).json({ error: 'Location ID and text are required' });
            }
            
            try {
                const client = await getClient();
                const commentsCol = client.db(DB).collection(COMMENTS_COL);
                const { ObjectId } = await import('mongodb');
                
                const comment = {
                    locationId: new ObjectId(locationId),
                    userId: new ObjectId(userId),
                    text: text.trim(),
                    votes: [],
                    createdAt: new Date()
                };
                const result = await commentsCol.insertOne(comment);
                return res.status(200).json({ success: true, commentId: result.insertedId.toString() });
            } catch (err) {
                console.error('Post comment error:', err);
                return res.status(500).json({ error: 'Failed to post comment' });
            }
        }
        
        return res.status(405).json({ error: 'Method not allowed' });
    }
    
    if (url === '/api/comments/vote' || url === '/vote-comment') {
        if (setMethodHeaders(['POST'])) return;
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        const { commentId, voteType } = req.body;
        if (!commentId || (voteType !== 'up' && voteType !== 'down')) {
            return res.status(400).json({ error: 'Invalid request' });
        }
        
        try {
            const client = await getClient();
            const commentsCol = client.db(DB).collection(COMMENTS_COL);
            const { ObjectId } = await import('mongodb');
            
            const comment = await commentsCol.findOne({ _id: new ObjectId(commentId) });
            if (!comment) return res.status(404).json({ error: 'Comment not found' });
            
            const existingVoteIndex = comment.votes?.findIndex(v => v.userId === userId);
            
            if (existingVoteIndex !== undefined && existingVoteIndex >= 0) {
                if (comment.votes[existingVoteIndex].type === voteType) {
                    await commentsCol.updateOne({ _id: new ObjectId(commentId) }, { $pull: { votes: { userId: userId } } });
                } else {
                    await commentsCol.updateOne({ _id: new ObjectId(commentId) }, { $set: { [`votes.${existingVoteIndex}.type`]: voteType } });
                }
            } else {
                await commentsCol.updateOne({ _id: new ObjectId(commentId) }, { $push: { votes: { userId: userId, type: voteType } } });
            }
            
            const updatedComment = await commentsCol.findOne({ _id: new ObjectId(commentId) });
            const upvotes = updatedComment.votes?.filter(v => v.type === 'up').length || 0;
            const downvotes = updatedComment.votes?.filter(v => v.type === 'down').length || 0;
            
            return res.status(200).json({ success: true, upvotes: upvotes, downvotes: downvotes });
        } catch (err) {
            console.error('Vote comment error:', err);
            return res.status(500).json({ error: 'Failed to vote' });
        }
    }
    
    // ==================== UNLOCKED LOCATIONS ====================
    if (url === '/api/user-unlocked-locations' || url === '/unlocked-locations') {
        if (method === 'OPTIONS') {
            setCorsHeaders(res);
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
            return res.status(200).end();
        }
        setCorsHeaders(res);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        try {
            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            if (method === 'GET') {
                const user = await usersCol.findOne({ _id: new ObjectId(userId) });
                return res.status(200).json({ unlockedLocationIds: user?.unlockedLocations || [] });
            } else if (method === 'POST') {
                const { locationIds } = req.body;
                await usersCol.updateOne({ _id: new ObjectId(userId) }, {
                    $set: { unlockedLocations: locationIds, hasInitialLocations: true }
                });
                return res.status(200).json({ success: true });
            }
            return res.status(405).json({ error: 'Method not allowed' });
        } catch (err) {
            console.error('Unlocked locations error:', err);
            return res.status(500).json({ error: 'Failed to process request' });
        }
    }
    
    // ==================== UPLOAD ENDPOINTS ====================
    if (url === '/api/upload/photo' || url === '/upload-photo') {
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        const form = new formidable.IncomingForm();
        form.parse(req, async (err, fields, files) => {
            if (err) return res.status(500).json({ error: 'Upload failed' });
            
            const file = files.photo;
            if (!file) return res.status(400).json({ error: 'No file uploaded' });
            
            try {
                const result = await cloudinary.uploader.upload(file.filepath, {
                    folder: 'vestige/profiles',
                    transformation: [{ width: 500, height: 500, crop: 'fill' }]
                });
                
                const client = await getClient();
                const usersCol = client.db(DB).collection(USERS_COL);
                const { ObjectId } = await import('mongodb');
                await usersCol.updateOne({ _id: new ObjectId(userId) }, { $set: { profilePic: result.secure_url } });
                fs.unlinkSync(file.filepath);
                return res.status(200).json({ photoUrl: result.secure_url });
            } catch (error) {
                console.error('Cloudinary error:', error);
                return res.status(500).json({ error: 'Upload failed' });
            }
        });
        return;
    }
    
    if (url === '/api/upload/cover' || url === '/upload-cover') {
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        const form = new formidable.IncomingForm();
        form.parse(req, async (err, fields, files) => {
            if (err) return res.status(500).json({ error: 'Upload failed' });
            
            const file = files.photo;
            if (!file) return res.status(400).json({ error: 'No file uploaded' });
            
            try {
                const result = await cloudinary.uploader.upload(file.filepath, {
                    folder: 'vestige/covers',
                    transformation: [{ width: 1200, height: 400, crop: 'fill' }]
                });
                
                const client = await getClient();
                const usersCol = client.db(DB).collection(USERS_COL);
                const { ObjectId } = await import('mongodb');
                await usersCol.updateOne({ _id: new ObjectId(userId) }, { $set: { coverPhoto: result.secure_url } });
                fs.unlinkSync(file.filepath);
                return res.status(200).json({ photoUrl: result.secure_url });
            } catch (error) {
                console.error('Cloudinary error:', error);
                return res.status(500).json({ error: 'Upload failed' });
            }
        });
        return;
    }
    
    if (url === '/api/upload/location-image' || url === '/upload-image') {
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
        
        const cookieHeader = req.headers.cookie;
        if (!cookieHeader) return res.status(401).json({ error: 'Not authenticated' });
        
        const cookies = {};
        cookieHeader.split(';').forEach(cookie => {
            const [key, value] = cookie.trim().split('=');
            cookies[key] = value;
        });
        const token = cookies.auth_token;
        if (!token) return res.status(401).json({ error: 'Not authenticated' });
        
        try { jwt.verify(token, process.env.JWT_SECRET); } catch (err) { return res.status(401).json({ error: 'Invalid token' }); }
        
        const form = new formidable.IncomingForm();
        form.parse(req, async (err, fields, files) => {
            if (err) return res.status(500).json({ error: 'Failed to parse form data' });
            
            const file = files.photo;
            if (!file) return res.status(400).json({ error: 'No file uploaded' });
            
            try {
                const result = await cloudinary.uploader.upload(file.filepath, {
                    folder: 'vestige/locations',
                    transformation: [{ width: 1200, height: 1200, crop: 'limit', quality: 'auto' }]
                });
                try { fs.unlinkSync(file.filepath); } catch (e) {}
                return res.status(200).json({ success: true, photoUrl: result.secure_url });
            } catch (uploadError) {
                console.error('Cloudinary upload error:', uploadError);
                return res.status(500).json({ error: 'Failed to upload to cloud storage' });
            }
        });
        return;
    }
    
    // ==================== LOCATION SUBMISSION (CREATE) ====================
    if (url === '/api/locations-create' || url === '/locations/create') {
        if (setMethodHeaders(['POST'])) return;
        
        const userId = getUserIdFromCookie(req);
        if (!userId) return res.status(401).json({ error: 'Not authenticated' });
        
        const { locationId } = req.body;
        if (!locationId) return res.status(400).json({ error: 'Location ID required' });
        
        try {
            const client = await getClient();
            const locationsCol = client.db(DB).collection(LOCATIONS_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const user = await usersCol.findOne({ _id: new ObjectId(userId) });
            const unclaimedIds = user.unclaimedLocationIds || [];
            if (!unclaimedIds.includes(locationId)) {
                return res.status(400).json({ error: 'Location not available to claim' });
            }
            
            await usersCol.updateOne({ _id: new ObjectId(userId) }, {
                $pull: { unclaimedLocationIds: locationId },
                $addToSet: { earnedLocationIds: locationId }
            });
            
            await locationsCol.updateOne({ _id: new ObjectId(locationId) }, { $inc: { visitorCount: 1 } });
            
            return res.status(200).json({ success: true, message: 'Location claimed and explored!' });
        } catch (err) {
            console.error('Visit location error:', err);
            return res.status(500).json({ error: 'Failed to claim location' });
        }
    }
    
    // ==================== DEFAULT 404 ====================
    return res.status(404).json({ error: `Endpoint not found: ${url}` });
}