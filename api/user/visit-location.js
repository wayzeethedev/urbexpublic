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

    const { locationId } = req.body;
    if (!locationId) {
        return res.status(400).json({ error: 'Location ID required' });
    }

    try {
        const client = await getClient();
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const usersCol = client.db(DB).collection(USERS_COL);
        const { ObjectId } = await import('mongodb');

        const user = await usersCol.findOne({ _id: new ObjectId(userId) });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const location = await locationsCol.findOne({ _id: new ObjectId(locationId) });
        if (!location) {
            return res.status(404).json({ error: 'Location not found' });
        }

        const hasVisited = user.visitedLocationIds && user.visitedLocationIds.includes(locationId);
        
        if (!hasVisited) {
            await usersCol.updateOne(
                { _id: new ObjectId(userId) },
                { 
                    $addToSet: { 
                        visitedLocationIds: locationId,
                        earnedLocationIds: locationId
                    }
                }
            );

            const visitorIds = location.visitorIds || [];
            if (!visitorIds.includes(userId)) {
                visitorIds.push(userId);
                const newVisitorCount = visitorIds.length;
                
                await locationsCol.updateOne(
                    { _id: new ObjectId(locationId) },
                    { 
                        $set: { 
                            visitorCount: newVisitorCount,
                            visitorIds: visitorIds
                        }
                    }
                );
            }

            return res.status(200).json({ 
                success: true, 
                message: 'Location marked as visited!',
                isConfirmed: location.visitorCount + 1 > 1
            });
        }

        return res.status(200).json({ 
            success: true, 
            message: 'Already visited this location',
            isConfirmed: location.visitorCount > 1
        });

    } catch (err) {
        console.error('Visit location error:', err);
        return res.status(500).json({ error: 'Failed to process visit' });
    }
}