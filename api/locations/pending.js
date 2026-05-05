import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const LOCATIONS_COL = 'locations';
const USERS_COL = 'users';

let cachedClient = null;

async function getClient() {
    if (cachedClient) return cachedClient;
    if (!uri) throw new Error('MONGODB_URI is not defined');
    const client = new MongoClient(uri);
    await client.connect();
    cachedClient = client;
    return client;
}

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
        // Check if user is admin (you can set admin emails in env)
        const adminEmails = (process.env.ADMIN_EMAILS || '').split(',');
        return adminEmails.includes(decoded.email);
    } catch {
        return false;
    }
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // Check if user is admin
    if (!isAdmin(req)) {
        return res.status(403).json({ error: 'Forbidden - Admin only' });
    }

    try {
        const client = await getClient();
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const usersCol = client.db(DB).collection(USERS_COL);
        
        const pendingLocations = await locationsCol.find({ status: 'pending' })
            .sort({ createdAt: -1 })
            .toArray();
        
        // Get user info for each location
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
        
        return res.status(200).json({ 
            success: true, 
            locations: locationsWithUser 
        });
        
    } catch (err) {
        console.error('Get pending locations error:', err);
        return res.status(500).json({ error: 'Failed to get pending locations' });
    }
}