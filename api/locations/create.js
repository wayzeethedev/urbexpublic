// Add this endpoint for when a user visits/claims a location
// api/locations/visit.js

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

    const userId = getUserIdFromCookie(req);
    if (!userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { locationId } = req.body;
    if (!locationId) {
        return res.status(400).json({ error: 'Location ID required' });
    }

    try {
        const client = await getClient();
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const usersCol = client.db(DB).collection(USERS_COL);
        const { ObjectId } = await import('mongodb');

        // Check if location is in user's unclaimed list
        const user = await usersCol.findOne({ _id: new ObjectId(userId) });
        const unclaimedIds = user.unclaimedLocationIds || [];
        
        if (!unclaimedIds.includes(locationId)) {
            return res.status(400).json({ error: 'Location not available to claim' });
        }

        // Move from unclaimed to earned
        await usersCol.updateOne(
            { _id: new ObjectId(userId) },
            {
                $pull: { unclaimedLocationIds: locationId },
                $addToSet: { earnedLocationIds: locationId }
            }
        );

        // Increment visitor count for the location
        await locationsCol.updateOne(
            { _id: new ObjectId(locationId) },
            { $inc: { visitorCount: 1 } }
        );

        return res.status(200).json({
            success: true,
            message: 'Location claimed and explored!'
        });

    } catch (err) {
        console.error('Visit location error:', err);
        return res.status(500).json({ error: 'Failed to claim location' });
    }
}