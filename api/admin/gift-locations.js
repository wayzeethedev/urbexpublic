import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
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
        const adminEmails = (process.env.ADMIN_EMAILS || '').split(',');
        return adminEmails.includes(decoded.email);
    } catch {
        return false;
    }
}

export default async function handler(req, res) {
    const allowedOrigin = process.env.ALLOWED_ORIGINS || 'http://localhost:3000';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    if (!isAdmin(req)) {
        return res.status(403).json({ error: 'Forbidden - Admin only' });
    }

    const { userId, locationIds } = req.body;
    
    if (!userId) {
        return res.status(400).json({ error: 'User ID required' });
    }
    
    if (!locationIds || !locationIds.length) {
        return res.status(400).json({ error: 'Location IDs required' });
    }

    try {
        const client = await getClient();
        const usersCol = client.db(DB).collection(USERS_COL);
        const { ObjectId } = await import('mongodb');
        
        const userIds = Array.isArray(userId) ? userId.map(id => new ObjectId(id)) : [new ObjectId(userId)];
        
        for (const uid of userIds) {
            await usersCol.updateOne(
                { _id: uid },
                { $addToSet: { earnedLocationIds: { $each: locationIds } } }
            );
        }
        
        const count = userIds.length;
        return res.status(200).json({ 
            success: true, 
            message: `Gifted ${locationIds.length} locations to ${count} user${count !== 1 ? 's' : ''}` 
        });
        
    } catch (err) {
        console.error('Gift locations error:', err);
        return res.status(500).json({ error: 'Failed to gift locations' });
    }
}