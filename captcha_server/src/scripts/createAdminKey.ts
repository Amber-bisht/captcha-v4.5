import crypto from 'crypto';
import mongoose from 'mongoose';
import AdminKeyModel from '../models/AdminKey';
import { connectMongo } from '../config/mongo';

const generateKey = async () => {
    await connectMongo();

    const rawKey = crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(rawKey).digest('hex');

    const name = process.argv[2] || 'Default Admin Key';

    try {
        const newKey = await AdminKeyModel.create({
            keyHash: hashed,
            name
        });

        console.log('\n✅ Admin Key Created Successfully!');
        console.log('-----------------------------------');
        console.log(`Name: ${newKey.name}`);
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
