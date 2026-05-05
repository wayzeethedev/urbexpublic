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

    const admin = getAdminInfo(req);
    if (!admin) {
        return res.status(403).json({ error: 'Forbidden - Admin only' });
    }

    const { locationId, action, points, deniedReason } = req.body;

    if (!locationId) {
        return res.status(400).json({ error: 'Location ID is required' });
    }

    if (action !== 'approve' && action !== 'deny') {
        return res.status(400).json({ error: 'Action must be approve or deny' });
    }

    try {
        const client = await getClient();
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const usersCol = client.db(DB).collection(USERS_COL);
        const { ObjectId } = await import('mongodb');

        const location = await locationsCol.findOne({ _id: new ObjectId(locationId) });
        
        if (!location) {
            return res.status(404).json({ error: 'Location not found' });
        }

        if (location.status !== 'pending') {
            return res.status(400).json({ error: 'Location already processed' });
        }

        if (action === 'approve') {
            if (!points || points < 2 || points > 20) {
                return res.status(400).json({ error: 'Points must be between 2 and 20' });
            }

            const creatorId = location.createdBy.toString();
            const visitorIds = [creatorId];

            await locationsCol.updateOne(
                { _id: new ObjectId(locationId) },
                { 
                    $set: { 
                        status: 'approved',
                        points: points,
                        visitorCount: 1,
                        visitorIds: visitorIds,
                        approvedBy: new ObjectId(admin.userId),
                        approvedAt: new Date()
                    }
                }
            );

            await usersCol.updateOne(
                { _id: location.createdBy },
                { 
                    $inc: { points: points },
                    $addToSet: { 
                        earnedLocationIds: locationId,
                        visitedLocationIds: locationId
                    },
                    $push: { 
                        contributedLocations: {
                            locationId: new ObjectId(locationId),
                            title: location.title,
                            points: points,
                            approvedAt: new Date()
                        }
                    }
                }
            );

            return res.status(200).json({ 
                success: true, 
                message: `Location approved! User earned ${points} points and automatically unlocked this location.`
            });

        } else if (action === 'deny') {
            await locationsCol.updateOne(
                { _id: new ObjectId(locationId) },
                { 
                    $set: { 
                        status: 'denied',
                        deniedReason: deniedReason || 'No reason provided',
                        approvedBy: new ObjectId(admin.userId),
                        approvedAt: new Date()
                    }
                }
            );

            return res.status(200).json({ 
                success: true, 
                message: 'Location denied'
            });
        }

    } catch (err) {
        console.error('Approve/deny error:', err);
        return res.status(500).json({ error: 'Failed to process location: ' + err.message });
    }
}