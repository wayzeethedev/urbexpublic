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

    const { userId, username, firstName, lastName, email, points } = req.body;
    
    if (!userId) {
        return res.status(400).json({ error: 'User ID required' });
    }

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
        
        const result = await usersCol.updateOne(
            { _id: new ObjectId(userId) },
            { $set: updateData }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        return res.status(200).json({ success: true, message: 'User updated' });
        
    } catch (err) {
        console.error('Update user error:', err);
        return res.status(500).json({ error: 'Failed to update user' });
    }
}