import mongoose, { Schema, Document } from 'mongoose';

export interface IAdminKey extends Document {
    keyHash: string; // SHA-256 hash of the API key
    name: string;    // Description (e.g. "Dev Team Key")
    createdAt: Date;
}

const AdminKeySchema: Schema = new Schema({
    keyHash: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

export default mongoose.model<IAdminKey>('AdminKey', AdminKeySchema);
