import { MongoClient } from 'mongodb';
import bcrypt from 'bcrypt';

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

  const { token, username, password, acceptedTerms } = req.body;

  if (!token || !/^\d{12}$/.test(token)) {
    return res.status(400).json({ error: 'Valid access token is required.' });
  }

  if (!username || username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'Username must be 3-30 characters.' });
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores.' });
  }

  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  if (!acceptedTerms) {
    return res.status(400).json({ error: 'You must accept the terms and policies.' });
  }

  try {
    const client = await getClient();
    const requestsCol = client.db(DB).collection(COL);
    const usersCol = client.db(DB).collection(USERS_COL);

    // Verify token exists and hasn't been used
    const request = await requestsCol.findOne({ 
      accessToken: token,
      registeredAt: { $exists: false } // Not registered yet
    });

    if (!request) {
      return res.status(401).json({ error: 'Invalid or already used access token.' });
    }

    // Check if username already exists
    const existingUsername = await usersCol.findOne({ username: username.toLowerCase() });
    if (existingUsername) {
      return res.status(409).json({ error: 'Username already taken. Please choose another.' });
    }

    // Check if email already registered
    const existingEmail = await usersCol.findOne({ email: request.email });
    if (existingEmail) {
      return res.status(409).json({ error: 'This email has already been registered.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    await usersCol.insertOne({
      username: username.toLowerCase(),
      email: request.email,
      firstName: request.firstName,
      lastName: request.lastName,
      password: hashedPassword,
      accessToken: token,
      createdAt: new Date(),
      lastLogin: null
    });

    // Mark token as used
    await requestsCol.updateOne(
      { accessToken: token },
      { $set: { registeredAt: new Date() } }
    );

    return res.status(200).json({ 
      ok: true, 
      message: 'Registration successful! You can now login.'
    });

  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'Failed to complete registration.' });
  }
}