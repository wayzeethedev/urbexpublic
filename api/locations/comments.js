import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const COMMENTS_COL = 'comments';
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
    console.log('Comments API called. Method:', req.method);
    console.log('Query:', req.query);
    
    const allowedOrigin = process.env.ALLOWED_ORIGINS || 'http://localhost:3000';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Handle GET request - fetch comments for a location
    if (req.method === 'GET') {
        const { locationId } = req.query;
        
        console.log('GET request - Location ID:', locationId);
        
        if (!locationId) {
            return res.status(400).json({ error: 'Location ID required' });
        }

        try {
            const client = await getClient();
            const commentsCol = client.db(DB).collection(COMMENTS_COL);
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');
            
            const comments = await commentsCol.find({ locationId: new ObjectId(locationId) })
                .sort({ createdAt: -1 })
                .toArray();
            
            console.log('Found comments count:', comments.length);
            
            const userId = getUserIdFromCookie(req);
            
            const commentsWithUsernames = await Promise.all(comments.map(async (comment) => {
                let username = 'Unknown';
                if (comment.userId) {
                    const user = await usersCol.findOne({ _id: comment.userId });
                    if (user) {
                        username = user.username;
                    }
                }
                
                const userVote = comment.votes?.find(v => v.userId === userId);
                
                return {
                    _id: comment._id.toString(),
                    username: username,
                    text: comment.text,
                    createdAt: comment.createdAt,
                    upvotes: comment.votes?.filter(v => v.type === 'up').length || 0,
                    downvotes: comment.votes?.filter(v => v.type === 'down').length || 0,
                    userVote: userVote?.type || null
                };
            }));
            
            return res.status(200).json({ comments: commentsWithUsernames });
            
        } catch (err) {
            console.error('Get comments error:', err);
            return res.status(500).json({ error: 'Failed to get comments: ' + err.message });
        }
    }

    // Handle POST request - add new comment
    if (req.method === 'POST') {
        console.log('POST request - Adding new comment');
        
        const userId = getUserIdFromCookie(req);
        if (!userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const { locationId, text } = req.body;
        if (!locationId || !text || !text.trim()) {
            return res.status(400).json({ error: 'Location ID and text are required' });
        }

        try {
            const client = await getClient();
            const commentsCol = client.db(DB).collection(COMMENTS_COL);
            const { ObjectId } = await import('mongodb');
            
            const comment = {
                locationId: new ObjectId(locationId),
                userId: new ObjectId(userId),
                text: text.trim(),
                votes: [],
                createdAt: new Date()
            };
            
            const result = await commentsCol.insertOne(comment);
            
            return res.status(200).json({ 
                success: true, 
                commentId: result.insertedId.toString()
            });
            
        } catch (err) {
            console.error('Post comment error:', err);
            return res.status(500).json({ error: 'Failed to post comment' });
        }
    }

    return res.status(405).json({ error: 'Method not allowed' });
}