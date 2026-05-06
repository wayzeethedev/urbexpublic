import { MongoClient } from 'mongodb';

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

export default async function handler(req, res) {
    const allowedOrigin = process.env.ALLOWED_ORIGINS || 'http://localhost:3000';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const client = await getClient();
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const usersCol = client.db(DB).collection(USERS_COL);
        
        const locations = await locationsCol.find({ status: 'approved' })
            .sort({ createdAt: -1 })
            .toArray();
        
        // Get submitter usernames for each location
        const locationsWithSubmitters = await Promise.all(locations.map(async (location) => {
            let submitterUsername = 'unknown';
            if (location.createdBy) {
                const submitter = await usersCol.findOne({ _id: location.createdBy });
                if (submitter) {
                    submitterUsername = submitter.username;
                }
            }
            return {
                ...location,
                submitterUsername: submitterUsername
            };
        }));
        
        return res.status(200).json({ 
            success: true, 
            locations: locationsWithSubmitters 
        });
        
    } catch (err) {
        console.error('Get approved locations error:', err);
        return res.status(500).json({ error: 'Failed to get locations' });
    }
}