import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

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
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const userId = getUserIdFromCookie(req);
  if (!userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const { displayName, bio, location, theme, emailNotifications, publicProfile } = req.body;

  try {
    const client = await getClient();
    const usersCol = client.db(DB).collection(USERS_COL);
    const { ObjectId } = await import('mongodb');
    
    await usersCol.updateOne(
      { _id: new ObjectId(userId) },
      { 
        $set: {
          displayName,
          bio,
          location,
          theme,
          emailNotifications,
          publicProfile,
          updatedAt: new Date()
        }
      }
    );
    
    return res.status(200).json({ ok: true, message: 'Profile updated' });
    
  } catch (err) {
    console.error('Update error:', err);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
}