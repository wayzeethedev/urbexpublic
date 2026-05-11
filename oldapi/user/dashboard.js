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
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const userId = getUserIdFromCookie(req);
    if (!userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const client = await getClient();
        const usersCol = client.db(DB).collection(USERS_COL);
        const locationsCol = client.db(DB).collection(LOCATIONS_COL);
        const { ObjectId } = await import('mongodb');

        const user = await usersCol.findOne({ _id: new ObjectId(userId) });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const signupDate = new Date(user.signupDate || user.createdAt);
        const today = new Date();
        const daysSinceSignup = Math.floor((today - signupDate) / (1000 * 60 * 60 * 24));
        
        const earnedIds = user.earnedLocationIds || [];
        const earnedLocations = earnedIds.length > 0 ? await locationsCol.find({ 
            _id: { $in: earnedIds.map(id => new ObjectId(id)) } 
        }).toArray() : [];
        
        const unclaimedIds = user.unclaimedLocationIds || [];
        const unclaimedLocations = unclaimedIds.length > 0 ? await locationsCol.find({ 
            _id: { $in: unclaimedIds.map(id => new ObjectId(id)) } 
        }).toArray() : [];
        
        const visitedIds = user.visitedLocationIds || [];
        const contributedLocations = user.contributedLocations || [];
        
        // Get submitter usernames for earned locations
        const earnedWithSubmitters = await Promise.all(earnedLocations.map(async (loc) => {
            let submitterUsername = 'unknown';
            if (loc.createdBy) {
                const submitter = await usersCol.findOne({ _id: loc.createdBy });
                if (submitter) {
                    submitterUsername = submitter.username;
                }
            }
            return { ...loc, submitterUsername };
        }));
        
        // Get submitter usernames for unclaimed locations
        const unclaimedWithSubmitters = await Promise.all(unclaimedLocations.map(async (loc) => {
            let submitterUsername = 'unknown';
            if (loc.createdBy) {
                const submitter = await usersCol.findOne({ _id: loc.createdBy });
                if (submitter) {
                    submitterUsername = submitter.username;
                }
            }
            return { ...loc, submitterUsername };
        }));
        
        return res.status(200).json({
            success: true,
            user: {
                username: user.username,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                points: user.points || 0,
                signupDate: signupDate,
                daysSinceSignup: daysSinceSignup,
                dailyLocationsClaimed: user.dailyLocationsClaimed || 0,
                redeemedLocations: user.redeemedLocations || 0,
                earnedLocationCount: earnedIds.length,
                unclaimedLocationCount: unclaimedIds.length,
                visitedLocationCount: visitedIds.length,
                totalLocationsUnlocked: earnedIds.length + unclaimedIds.length,
                hasReceivedWelcomeLocations: user.hasReceivedWelcomeLocations || false,
                contributedLocations: contributedLocations
            },
            earnedLocations: earnedWithSubmitters,
            unclaimedLocations: unclaimedWithSubmitters,
            visitedLocationIds: visitedIds
        });
        
    } catch (err) {
        console.error('Dashboard error:', err);
        return res.status(500).json({ error: 'Failed to load dashboard' });
    }
}