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

    try {
        const client = await getClient();
        const usersCol = client.db(DB).collection(USERS_COL);
        const { ObjectId } = await import('mongodb');

        const user = await usersCol.findOne({ _id: new ObjectId(userId) });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const unclaimedIds = user.unclaimedLocationIds || [];
        
        if (unclaimedIds.length === 0) {
            return res.status(200).json({
                success: true,
                claimedCount: 0,
                message: 'No locations to claim'
            });
        }
        
        await usersCol.updateOne(
            { _id: new ObjectId(userId) },
            {
                $pull: { unclaimedLocationIds: { $in: unclaimedIds } },
                $addToSet: { earnedLocationIds: { $each: unclaimedIds } }
            }
        );
        
        return res.status(200).json({
            success: true,
            claimedCount: unclaimedIds.length,
            message: `Claimed ${unclaimedIds.length} locations!`
        });
        
    } catch (err) {
        console.error('Claim all error:', err);
        return res.status(500).json({ error: 'Failed to claim locations' });
    }
}