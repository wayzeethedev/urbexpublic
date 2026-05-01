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
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const userId = getUserIdFromCookie(req);
    if (!userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { title, description, images, level, tags, coordinates } = req.body;

    if (!title || !description) {
        return res.status(400).json({ error: 'Title and description are required' });
    }

    try {
        const client = await getClient();
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const { ObjectId } = await import('mongodb');

        const location = {
            title,
            description,
            images: images || [],
            level: level,
            tags: tags || [],
            coordinates,
            createdBy: new ObjectId(userId),
            createdAt: new Date(),
            updatedAt: new Date(),
            likes: 0,
            points: calculatePoints(level.value)
        };

        const result = await locationsCol.insertOne(location);

        return res.status(200).json({ 
            ok: true, 
            message: 'Location created successfully',
            locationId: result.insertedId
        });

    } catch (err) {
        console.error('Create location error:', err);
        return res.status(500).json({ error: 'Failed to create location' });
    }
}

function calculatePoints(level) {
    const pointsMap = {
        'beginner': 10,
        'intermediate': 25,
        'advanced': 50,
        'expert': 100
    };
    return pointsMap[level] || 10;
}