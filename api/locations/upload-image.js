import { v2 as cloudinary } from 'cloudinary';
import formidable from 'formidable-serverless';
import fs from 'fs';
import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Disable body parser for this endpoint
export const config = {
    api: {
        bodyParser: false,
    },
};

export default async function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Only allow POST
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // Check authentication
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const cookies = {};
    cookieHeader.split(';').forEach(cookie => {
        const [key, value] = cookie.trim().split('=');
        cookies[key] = value;
    });

    const token = cookies.auth_token;
    if (!token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        // Verify JWT
        jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Parse form data
    const form = new formidable.IncomingForm();
    form.uploadDir = '/tmp';
    form.keepExtensions = true;
    
    form.parse(req, async (err, fields, files) => {
        if (err) {
            console.error('Form parse error:', err);
            return res.status(500).json({ error: 'Failed to parse form data' });
        }

        // Get the uploaded file (field name is 'photo')
        const file = files.photo;
        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        try {
            // Upload to Cloudinary
            const result = await cloudinary.uploader.upload(file.filepath, {
                folder: 'vestige/locations',
                transformation: [
                    { width: 1200, height: 1200, crop: 'limit', quality: 'auto' }
                ]
            });

            // Clean up temp file
            try {
                fs.unlinkSync(file.filepath);
            } catch (unlinkError) {
                console.error('Failed to delete temp file:', unlinkError);
            }

            // Return the URL
            return res.status(200).json({ 
                success: true, 
                photoUrl: result.secure_url 
            });

        } catch (uploadError) {
            console.error('Cloudinary upload error:', uploadError);
            return res.status(500).json({ error: 'Failed to upload to cloud storage' });
        }
    });
}