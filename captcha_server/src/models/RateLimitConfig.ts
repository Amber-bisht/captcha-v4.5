import mongoose, { Schema, Document } from 'mongoose';

export interface IRateLimitConfig extends Document {
    endpoint: string;
    windowMs: number;
    maxRequests: number;
    message?: string;
    isActive: boolean;
    updatedAt: Date;
}

const RateLimitConfigSchema: Schema = new Schema({
    endpoint: { type: String, required: true, unique: true },
    windowMs: { type: Number, required: true },
    maxRequests: { type: Number, required: true },
    message: { type: String },
    isActive: { type: Boolean, default: true },
    updatedAt: { type: Date, default: Date.now }
});

export default mongoose.model<IRateLimitConfig>('RateLimitConfig', RateLimitConfigSchema);
