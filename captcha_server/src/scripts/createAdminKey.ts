import crypto from 'crypto';
import mongoose from 'mongoose';
import AdminKeyModel from '../models/AdminKey';
import { connectMongo } from '../config/mongo';

const generateKey = async () => {
    await connectMongo();

    const rawKey = crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(rawKey).digest('hex');

    const description = process.argv[2] || 'Default Admin Key';

    try {
        const newKey = await AdminKeyModel.create({
            keyHash: hashed,
            description,
            permissions: ['all'],
            isActive: true
        });

        console.log('\n✅ Admin Key Created Successfully!');
        console.log('-----------------------------------');
        console.log(`Description: ${newKey.description}`);
        console.log(`KEY (SAVE THIS, IT WILL NOT BE SHOWN AGAIN):`);
        console.log(rawKey);
        console.log('-----------------------------------');

    } catch (error) {
        console.error('Error creating key:', error);
    } finally {
        mongoose.disconnect();
    }
};

generateKey();
