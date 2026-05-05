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

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
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

        let user = await usersCol.findOne({ _id: new ObjectId(userId) });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        let userLat = null, userLng = null;
        if (req.body && req.body.latitude && req.body.longitude) {
            userLat = req.body.latitude;
            userLng = req.body.longitude;
        }

        let allLocations = await locationsCol.find({ status: 'approved' }).toArray();
        let welcomeLocationsAdded = 0;
        
        if (!user.hasReceivedWelcomeLocations) {
            if (userLat && userLng && allLocations.length > 0) {
                const locationsWithDistance = allLocations.map(loc => {
                    const distance = calculateDistance(userLat, userLng, loc.coordinates.lat, loc.coordinates.lng);
                    return { ...loc, distance };
                });
                
                const nearest15 = locationsWithDistance
                    .sort((a, b) => a.distance - b.distance)
                    .slice(0, 15);
                
                const welcomeLocationIds = nearest15.map(loc => loc._id.toString());
                
                await usersCol.updateOne(
                    { _id: new ObjectId(userId) },
                    { 
                        $set: { hasReceivedWelcomeLocations: true },
                        $addToSet: { unclaimedLocationIds: { $each: welcomeLocationIds } }
                    }
                );
                
                welcomeLocationsAdded = welcomeLocationIds.length;
                
                user = await usersCol.findOne({ _id: new ObjectId(userId) });
            } else {
                await usersCol.updateOne(
                    { _id: new ObjectId(userId) },
                    { $set: { hasReceivedWelcomeLocations: true } }
                );
            }
        }

        const signupDate = new Date(user.signupDate || user.createdAt);
        const today = new Date();
        const daysSinceSignup = Math.floor((today - signupDate) / (1000 * 60 * 60 * 24));
        
        const dailyLocationsAvailable = Math.max(0, daysSinceSignup - (user.dailyLocationsClaimed || 0));
        const earnedLocationsAvailable = (user.points || 0) - (user.redeemedLocations || 0);
        
        const earnedIds = user.earnedLocationIds || [];
        const unclaimedIds = user.unclaimedLocationIds || [];
        const alreadyHaveIds = [...earnedIds, ...unclaimedIds];
        
        let availableLocations = allLocations.filter(loc => !alreadyHaveIds.includes(loc._id.toString()));
        
        if (userLat && userLng && availableLocations.length > 0) {
            availableLocations.forEach(loc => {
                loc.distance = calculateDistance(userLat, userLng, loc.coordinates.lat, loc.coordinates.lng);
            });
            availableLocations.sort((a, b) => a.distance - b.distance);
        }
        
        const dailyLocationsToAdd = Math.min(dailyLocationsAvailable, availableLocations.length);
        const newDailyLocations = availableLocations.slice(0, dailyLocationsToAdd);
        
        const earnedLocationsToAdd = Math.min(earnedLocationsAvailable, availableLocations.length - dailyLocationsToAdd);
        const newEarnedLocations = availableLocations.slice(dailyLocationsToAdd, dailyLocationsToAdd + earnedLocationsToAdd);
        
        const allNewUnclaimed = [...newDailyLocations, ...newEarnedLocations];
        const newUnclaimedIds = allNewUnclaimed.map(loc => loc._id.toString());
        
        if (newUnclaimedIds.length > 0) {
            const updateData = {
                $addToSet: { unclaimedLocationIds: { $each: newUnclaimedIds } }
            };
            
            if (dailyLocationsToAdd > 0) {
                updateData.$inc = { dailyLocationsClaimed: dailyLocationsToAdd };
            }
            
            if (earnedLocationsToAdd > 0) {
                updateData.$inc = { ...(updateData.$inc || {}), redeemedLocations: earnedLocationsToAdd };
            }
            
            await usersCol.updateOne({ _id: new ObjectId(userId) }, updateData);
        }
        
        const totalNewUnlocked = welcomeLocationsAdded + newUnclaimedIds.length;
        
        return res.status(200).json({
            success: true,
            welcomeLocationsAdded: welcomeLocationsAdded,
            daysSinceSignup,
            dailyLocationsClaimed: user.dailyLocationsClaimed || 0,
            dailyLocationsAvailable: dailyLocationsAvailable,
            dailyLocationsAdded: dailyLocationsToAdd,
            earnedLocationsAvailable: earnedLocationsAvailable,
            earnedLocationsAdded: earnedLocationsToAdd,
            totalNewUnlocked: totalNewUnlocked,
            newUnclaimedIds: newUnclaimedIds,
            isWelcome: welcomeLocationsAdded > 0
        });
        
    } catch (err) {
        console.error('Daily locations error:', err);
        return res.status(500).json({ error: 'Failed to process daily locations' });
    }
}