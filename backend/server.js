import express from 'express';
import { MongoClient } from 'mongodb';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// MongoDB configuration
const uri = "mongodb+srv://user1:tY9aa73O93kXBQtx@clusterog.cwuqkz9.mongodb.net/vestige?retryWrites=true&w=majority&appName=clusterog";
const DB = 'vestige';
const COL = 'invite_requests';

let cachedClient = null;

async function getClient() {
  if (cachedClient) return cachedClient;
  const client = new MongoClient(uri);
  await client.connect();
  console.log('✅ Connected to MongoDB');
  cachedClient = client;
  return client;
}

// API endpoint - NOTE: This is app.post, NOT app.all or app.use
app.post('/api/request', async (req, res) => {
  console.log('📨 POST request received');
  console.log('Body:', req.body);
  
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
    const col = client.db(DB).collection(COL);

    // Prevent duplicate requests from the same email
    const existing = await col.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'A request from this email already exists.' });
    }

    await col.insertOne({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      comments: comments?.trim() ?? '',
      status: 'pending',
      createdAt: new Date(),
    });

    console.log('✅ Saved successfully');
    return res.status(200).json({ ok: true, message: 'Request submitted successfully' });

  } catch (err) {
    console.error('MongoDB error:', err);
    return res.status(500).json({ error: 'Failed to save your request. Please try again.' });
  }
});

// Handle OPTIONS preflight requests
app.options('/api/request', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.status(200).end();
});

// Serve your HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(`📝 API endpoint: http://localhost:${PORT}/api/request`);
  console.log(`📋 Test with: curl -X POST http://localhost:${PORT}/api/request -H "Content-Type: application/json" -d '{"name":"Test","email":"test@test.com"}'`);
});