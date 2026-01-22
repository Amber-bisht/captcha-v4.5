import crypto from 'crypto';
import AdminKeyModel from '../models/AdminKey';
import { SecurityLogger } from '../utils/securityLogger';

export const seedAdminKey = async () => {
    try {
        const count = await AdminKeyModel.countDocuments();
        if (count === 0) {
            console.log('🔒 No Admin Keys found. Generating initial Admin Key...');

            const rawKey = crypto.randomBytes(32).toString('hex');
            const hashed = crypto.createHash('sha256').update(rawKey).digest('hex');

            await AdminKeyModel.create({
                keyHash: hashed,
                description: 'Auto-generated Initial Admin Key',
                permissions: ['all'],
                isActive: true
            });

            console.log(`
╔══════════════════════════════════════════════════════════════╗
║                 INITIAL ADMIN KEY GENERATED                  ║
╠══════════════════════════════════════════════════════════════╣
║ Key: ${rawKey}                                              ║
║                                                              ║
║ SAVE THIS KEY SAFELY! It will NOT be shown again.            ║
╚══════════════════════════════════════════════════════════════╝
            `);

            SecurityLogger.info('Initial Admin Key generated');
        } else {
            console.log('🔒 Admin Key system initialized (keys exist).');
        }
    } catch (error) {
        console.error('❌ Failed to seed Admin Key:', error);
    }
};
