import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
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

    const { title, description, images, level, tags, coordinates } = req.body;
    
    // Validate required fields
    if (!title || !description || !coordinates || !level) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!coordinates.lat || !coordinates.lng) {
        return res.status(400).json({ error: 'Valid coordinates are required' });
    }

    try {
        const client = await getClient();
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const { ObjectId } = await import('mongodb');

        // Create location object
        const newLocation = {
            title,
            description,
            images: images || [],
            level: level.value || level,
            tags: tags || [],
            coordinates: {
                type: 'Point',
                coordinates: [coordinates.lng, coordinates.lat] // GeoJSON format: [longitude, latitude]
            },
            createdBy: new ObjectId(userId),
            createdAt: new Date(),
            status: 'pending', // pending, approved, rejected
            visitorCount: 0,
            likes: 0
        };

        const result = await locationsCol.insertOne(newLocation);
        
        if (!result.acknowledged) {
            throw new Error('Failed to insert location');
        }

        return res.status(200).json({
            success: true,
            message: 'Location submitted for approval',
            locationId: result.insertedId
        });

    } catch (err) {
        console.error('Create location error:', err);
        return res.status(500).json({ error: 'Failed to create location' });
    }
}