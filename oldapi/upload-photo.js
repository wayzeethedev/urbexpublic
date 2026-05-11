import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';
import { v2 as cloudinary } from 'cloudinary';
import formidable from 'formidable-serverless';
import fs from 'fs';

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const uri = process.env.MONGODB_URI;
const DB = 'vestige';
const USERS_COL = 'users';

let cachedClient = null;

async function getClient() {
    if (cachedClient) return cachedClient;
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

export const config = {
    api: {
        bodyParser: false,
    },
};

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const userId = getUserIdFromCookie(req);
    if (!userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const form = new formidable.IncomingForm();
    form.parse(req, async (err, fields, files) => {
        if (err) {
            return res.status(500).json({ error: 'Upload failed' });
        }

        const file = files.photo;
        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        try {
            const result = await cloudinary.uploader.upload(file.filepath, {
                folder: 'vestige/profiles',
                transformation: [{ width: 500, height: 500, crop: 'fill' }]
            });

            const client = await getClient();
            const usersCol = client.db(DB).collection(USERS_COL);
            const { ObjectId } = await import('mongodb');

            await usersCol.updateOne(
                { _id: new ObjectId(userId) },
                { $set: { profilePic: result.secure_url } }
            );

            fs.unlinkSync(file.filepath);

            return res.status(200).json({ photoUrl: result.secure_url });
        } catch (error) {
            console.error('Cloudinary error:', error);
            return res.status(500).json({ error: 'Upload failed' });
        }
    });
}