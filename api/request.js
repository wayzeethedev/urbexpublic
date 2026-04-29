// Vercel serverless function — POST /api/request
// Saves invite requests to MongoDB.
//
// Required environment variable (set in Vercel project settings):
//   MONGODB_URI=mongodb+srv://<user>:<pass>@<cluster>.mongodb.net/<dbname>?retryWrites=true&w=majority

import { MongoClient } from 'mongodb';

const uri    = process.env.MONGODB_URI;
const DB     = 'vestige';
const COL    = 'invite_requests';

// Reuse client across warm invocations
let cachedClient = null;

async function getClient() {
  if (cachedClient) return cachedClient;
  const client = new MongoClient(uri);
  await client.connect();
  cachedClient = client;
  return client;
}

export default async function handler(req, res) {
  // Set CORS headers for local development
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

  // Server-side validation
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ error: 'Name is required.' });
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
    const col    = client.db(DB).collection(COL);

    // Prevent duplicate requests from the same email
    const existing = await col.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'A request from this email already exists.' });
    }

    await col.insertOne({
      name:      name.trim(),
      email:     email.toLowerCase().trim(),
      comments:  comments?.trim() ?? '',
      status:    'pending',   // pending | approved | denied
      createdAt: new Date(),
    });

    return res.status(200).json({ ok: true, message: 'Request submitted successfully' });

  } catch (err) {
    console.error('MongoDB error:', err);
    return res.status(500).json({ error: 'Failed to save your request. Please try again.' });
  }
}