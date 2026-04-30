import { MongoClient } from 'mongodb';

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const COL = 'invite_requests';

let cachedClient = null;

async function getClient() {
  if (cachedClient) return cachedClient;
  if (!uri) throw new Error('MONGODB_URI is not defined');
  const client = new MongoClient(uri);
  await client.connect();
  cachedClient = client;
  return client;
}

// Generate random 12-digit access token
function generateAccessToken() {
  return Math.floor(100000000000 + Math.random() * 900000000000).toString();
}

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { name, email, comments } = req.body ?? {};

  // Parse name into first and last
  const nameParts = name.trim().split(' ');
  const firstName = nameParts[0];
  const lastName = nameParts.slice(1).join(' ') || '';

  // Server-side validation
  if (!firstName || typeof firstName !== 'string' || firstName.trim().length === 0) {
    return res.status(400).json({ error: 'First name is required.' });
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'A valid email address is required.' });
  }

  if (!uri) {
    console.error('MONGODB_URI is not set.');
    return res.status(500).json({ error: 'Server configuration error.' });
  }

  try {
    const client = await getClient();
    const col = client.db(DB).collection(COL);

    // Prevent duplicate requests from the same email
    const existing = await col.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'A request from this email already exists.' });
    }

    // Generate unique access token (ensure it's not already used)
    let accessToken;
    let isUnique = false;
    
    while (!isUnique) {
      accessToken = generateAccessToken();
      const existingToken = await col.findOne({ accessToken: accessToken });
      if (!existingToken) {
        isUnique = true;
      }
    }

    await col.insertOne({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: email.toLowerCase().trim(),
      comments: comments?.trim() ?? '',
      status: 'pending',
      accessToken: accessToken, // Token assigned immediately
      createdAt: new Date(),
    });

    return res.status(200).json({ 
      ok: true, 
      message: 'Request submitted successfully. You will be notified when approved.',
      // Don't return the token to the user - you'll send it manually when approved
    });

  } catch (err) {
    console.error('MongoDB error:', err);
    return res.status(500).json({ error: 'Failed to save your request. Please try again.' });
  }
}