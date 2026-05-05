import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const COMMENTS_COL = 'comments';

let cachedClient = null;

async function getClient() {
    if (cachedClient) return cachedClient;
    if (!uri) throw new Error('MONGODB_URI is not defined');
    const client = new MongoClient(uri);
    await client.connect();
    cachedClient = client;
    return client;
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

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const userId = getUserIdFromCookie(req);
    if (!userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

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
        
        return res.status(200).json({ 
            success: true, 
            commentId: result.insertedId.toString()
        });
        
    } catch (err) {
        console.error('Post comment error:', err);
        return res.status(500).json({ error: 'Failed to post comment' });
    }
}