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

export default async function handler(req, res) {
  // Allow credentials and specific origin
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Get token from cookie
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    return res.status(401).json({ error: 'Not authenticated', authenticated: false });
  }

  // Parse cookies
  const cookies = {};
  cookieHeader.split(';').forEach(cookie => {
    const [key, value] = cookie.trim().split('=');
    cookies[key] = value;
  });

  const token = cookies.auth_token;

  if (!token) {
    return res.status(401).json({ error: 'Not authenticated', authenticated: false });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const client = await getClient();
    const usersCol = client.db(DB).collection(USERS_COL);
    
    // Get fresh user data from database
    const { ObjectId } = await import('mongodb');
    const user = await usersCol.findOne({ _id: new ObjectId(decoded.userId) });
    
    if (!user) {
      return res.status(401).json({ error: 'User not found', authenticated: false });
    }

    // Return user info (excluding password)
    return res.status(200).json({
      authenticated: true,
      user: {
        userId: user._id.toString(),
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        displayName: user.displayName
      }
    });

  } catch (err) {
    console.error('Auth check error:', err);
    return res.status(401).json({ error: 'Invalid or expired token', authenticated: false });
  }
}