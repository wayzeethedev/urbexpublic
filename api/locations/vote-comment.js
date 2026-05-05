import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const COMMENTS_COL = 'comments';

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

    const { commentId, voteType } = req.body;
    if (!commentId || (voteType !== 'up' && voteType !== 'down')) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    try {
        const client = await getClient();
        const commentsCol = client.db(DB).collection(COMMENTS_COL);
        const { ObjectId } = await import('mongodb');
        
        const comment = await commentsCol.findOne({ _id: new ObjectId(commentId) });
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found' });
        }
        
        const existingVoteIndex = comment.votes?.findIndex(v => v.userId === userId);
        
        if (existingVoteIndex !== undefined && existingVoteIndex >= 0) {
            if (comment.votes[existingVoteIndex].type === voteType) {
                await commentsCol.updateOne(
                    { _id: new ObjectId(commentId) },
                    { $pull: { votes: { userId: userId } } }
                );
            } else {
                await commentsCol.updateOne(
                    { _id: new ObjectId(commentId) },
                    { $set: { [`votes.${existingVoteIndex}.type`]: voteType } }
                );
            }
        } else {
            await commentsCol.updateOne(
                { _id: new ObjectId(commentId) },
                { $push: { votes: { userId: userId, type: voteType } } }
            );
        }
        
        const updatedComment = await commentsCol.findOne({ _id: new ObjectId(commentId) });
        const upvotes = updatedComment.votes?.filter(v => v.type === 'up').length || 0;
        const downvotes = updatedComment.votes?.filter(v => v.type === 'down').length || 0;
        
        return res.status(200).json({ 
            success: true, 
            upvotes: upvotes,
            downvotes: downvotes
        });
        
    } catch (err) {
        console.error('Vote comment error:', err);
        return res.status(500).json({ error: 'Failed to vote' });
    }
}