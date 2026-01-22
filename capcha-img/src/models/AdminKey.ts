import mongoose, { Schema, Document } from 'mongoose';

export interface IAdminKey extends Document {
    keyHash: string;
    description: string; // Updated from name
    permissions: string[];
    isActive: boolean;
    createdAt: Date;
}

const AdminKeySchema: Schema = new Schema({
    keyHash: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    permissions: { type: [String], default: [] },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

export default mongoose.model<IAdminKey>('AdminKey', AdminKeySchema);
