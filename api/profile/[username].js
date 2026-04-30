import { MongoClient } from 'mongodb';

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

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    const { username } = req.query;

    try {
        const client = await getClient();
        const usersCol = client.db(DB).collection(USERS_COL);
        
        const user = await usersCol.findOne({ username });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Return profile data (exclude sensitive info)
        return res.status(200).json({
            username: user.username,
            displayName: user.displayName || null,
            firstName: user.firstName,
            lastName: user.lastName,
            bio: user.bio || null,
            profilePic: user.profilePic || null,
            coverPhoto: user.coverPhoto || null,
            locationsUnlocked: user.locationsUnlocked || 0,
            locationsExplored: user.locationsExplored || 0,
            points: user.points || 0,
            totalLocations: 100
        });
        
    } catch (err) {
        console.error('Profile error:', err);
        return res.status(500).json({ error: 'Failed to load profile' });
    }
}