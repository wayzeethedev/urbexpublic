import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const USERS_COL = 'users';
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

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 3959;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}

function getNearestUnlockedLocations(userLocation, allLocations, earnedIds, count) {
    const availableLocations = allLocations.filter(loc => !earnedIds.includes(loc._id.toString()));
    
    const locationsWithDistance = availableLocations.map(loc => ({
        ...loc,
        distance: calculateDistance(userLocation.lat, userLocation.lng, loc.coordinates.lat, loc.coordinates.lng)
    }));
    
    return locationsWithDistance.sort((a, b) => a.distance - b.distance).slice(0, count);
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

    const { userIds, count } = req.body;
    
    if (!userIds || !userIds.length) {
        return res.status(400).json({ error: 'User IDs required' });
    }
    
    if (!count || count < 1) {
        return res.status(400).json({ error: 'Valid count required' });
    }

    try {
        const client = await getClient();
        const usersCol = client.db(DB).collection(USERS_COL);
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const { ObjectId } = await import('mongodb');
        
        const allLocations = await locationsCol.find({ status: 'approved' }).toArray();
        
        let totalGifted = 0;
        
        for (const userId of userIds) {
            const user = await usersCol.findOne({ _id: new ObjectId(userId) });
            if (!user) continue;
            
            const earnedIds = user.earnedLocationIds || [];
            
            let userLocation = null;
            if (user.lastLocation) {
                userLocation = user.lastLocation;
            } else if (user.unlockedLocations && user.unlockedLocations.length > 0) {
                const firstLocation = allLocations.find(l => l._id.toString() === user.unlockedLocations[0]);
                if (firstLocation) userLocation = firstLocation.coordinates;
            }
            
            if (!userLocation) {
                userLocation = { lat: 44.8614, lng: -92.6238 };
            }
            
            const nearestLocations = getNearestUnlockedLocations(userLocation, allLocations, earnedIds, count);
            
            if (nearestLocations.length > 0) {
                const locationIds = nearestLocations.map(loc => loc._id.toString());
                await usersCol.updateOne(
                    { _id: new ObjectId(userId) },
                    { $addToSet: { earnedLocationIds: { $each: locationIds } } }
                );
                totalGifted += locationIds.length;
            }
        }
        
        return res.status(200).json({ 
            success: true, 
            message: `Gifted ${totalGifted} locations to ${userIds.length} user${userIds.length !== 1 ? 's' : ''}` 
        });
        
    } catch (err) {
        console.error('Gift nearest locations error:', err);
        return res.status(500).json({ error: 'Failed to gift locations' });
    }
}