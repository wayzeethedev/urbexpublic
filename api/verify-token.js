import { MongoClient } from 'mongodb';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const COL = 'invite_requests';
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
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { token } = req.body;

  if (!token || !/^\d{12}$/.test(token)) {
    return res.status(400).json({ error: 'Valid 12-digit access token is required.' });
  }

  try {
    const client = await getClient();
    const col = client.db(DB).collection(COL);
    const usersCol = client.db(DB).collection(USERS_COL);

    // Find the request with this token (can be pending or approved - doesn't matter)
    const request = await col.findOne({ accessToken: token });

    if (!request) {
      return res.status(401).json({ error: 'Invalid access token.' });
    }

    // Check if user already registered
    const existingUser = await usersCol.findOne({ email: request.email });
    if (existingUser) {
      return res.status(409).json({ error: 'This access token has already been used.' });
    }

    return res.status(200).json({ 
      ok: true,
      firstName: request.firstName,
      lastName: request.lastName,
      email: request.email,
      token: token
    });

  } catch (err) {
    console.error('Token verification error:', err);
    return res.status(500).json({ error: 'Failed to verify access token.' });
  }
}