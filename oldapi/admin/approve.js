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

function generateAccessToken() {
  return Math.floor(100000000000 + Math.random() * 900000000000).toString();
}

export default async function handler(req, res) {
  // Protect this endpoint with a secret key
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_SECRET_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const client = await getClient();
    const col = client.db(DB).collection(COL);

    const accessToken = generateAccessToken();

    const result = await col.updateOne(
      { email: email.toLowerCase().trim(), status: 'pending' },
      { 
        $set: { 
          status: 'approved',
          accessToken: accessToken,
          approvedAt: new Date()
        } 
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Pending request not found' });
    }

    return res.status(200).json({ 
      ok: true, 
      accessToken: accessToken,
      message: `User approved. Send this access token to ${email}: ${accessToken}`
    });

  } catch (err) {
    console.error('Approval error:', err);
    return res.status(500).json({ error: 'Failed to approve request' });
  }
}