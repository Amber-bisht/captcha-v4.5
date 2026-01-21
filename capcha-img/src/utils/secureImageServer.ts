/**
 * Secure Image Serving System
 * Prevents image CAPTCHA bypass through filename/size/metadata analysis
 * 
 * UPDATED: Uses Redis for storage instead of in-memory Maps
 * FIXED: Stores targetCategory explicitly to prevent multi-user bugs
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import sharp from 'sharp';
import RedisStore from './redisStore';

export interface SecureImage {
    id: string;           // Random ID (sent to client)
    originalFile: string; // Actual filename (server-side only)
    category: string;     // Category (server-side only)
}

export interface SecureChallenge {
    sessionId: string;
    question: string;
    imageIds: string[];   // Only random IDs sent to client
    validAnswerIds: string[];
    targetCategory: string;  // FIXED: Store target category explicitly
    createdAt: number;
    expiresAt: number;
}

export class SecureImageServer {
    private imagesDir: string;
    private categories: Map<string, string[]> = new Map();
    private processedImagesDir: string;

    constructor(imagesDir: string) {
        this.imagesDir = imagesDir;
        this.processedImagesDir = path.join(imagesDir, '../processed');
        this.loadCategories();
    }

    /**
     * Load and categorize images from directory
     */
    private loadCategories(): void {
        if (!fs.existsSync(this.imagesDir)) {
            console.error('Images directory not found:', this.imagesDir);
            return;
        }

        const files = fs.readdirSync(this.imagesDir).filter(f =>
            /\.(jpg|jpeg|png|gif|webp)$/i.test(f)
        );

        files.forEach(file => {
            // Extract category from filename (e.g., "cat_1.jpg" -> "cat")
            const parts = file.split('_');
            if (parts.length > 1) {
                const category = parts[0].toLowerCase();
                if (!this.categories.has(category)) {
                    this.categories.set(category, []);
                }
                this.categories.get(category)!.push(file);
            }
        });

        console.log(`Loaded ${files.length} images in ${this.categories.size} categories`);

        // Log category breakdown
        this.categories.forEach((images, category) => {
            console.log(`  - ${category}: ${images.length} images`);
        });
    }

    /**
     * Reload categories (call when adding new images)
     */
    public reloadCategories(): void {
        this.categories.clear();
        this.loadCategories();
    }

    /**
     * Generate a secure challenge with randomized image IDs
     * FIXED: Now stores targetCategory explicitly in Redis
     */
    async generateSecureChallenge(gridSize: number = 9): Promise<SecureChallenge | null> {
        const categoryList = Array.from(this.categories.keys());
        if (categoryList.length < 2) {
            console.error('Need at least 2 categories for challenge');
            return null;
        }

        // Pick random target category
        const targetCategory = categoryList[Math.floor(Math.random() * categoryList.length)];
        const targetImages = this.categories.get(targetCategory) || [];
        const otherCategories = categoryList.filter(c => c !== targetCategory);

        // Get other images
        const otherImages: string[] = [];
        otherCategories.forEach(cat => {
            otherImages.push(...(this.categories.get(cat) || []));
        });

        if (targetImages.length < 2 || otherImages.length < 4) {
            console.error('Insufficient images for challenge');
            return null;
        }

        // Select 2-4 correct images
        const numCorrect = Math.min(
            Math.floor(Math.random() * 3) + 2, // 2-4
            targetImages.length
        );
        const shuffledTarget = this.shuffleArray([...targetImages]);
        const selectedCorrect = shuffledTarget.slice(0, numCorrect);

        // Fill rest with distractors
        const numDistractors = gridSize - numCorrect;
        const shuffledOther = this.shuffleArray([...otherImages]);
        const selectedDistractors = shuffledOther.slice(0, Math.min(numDistractors, shuffledOther.length));

        // Create session
        const sessionId = crypto.randomBytes(16).toString('hex');
        const now = Date.now();

        // Generate random IDs for each image (SECURITY: hide real filenames)
        const imageMap = new Map<string, SecureImage>();
        const allImages: SecureImage[] = [];
        const imageIds: string[] = [];

        for (const file of [...selectedCorrect, ...selectedDistractors]) {
            const id = crypto.randomBytes(8).toString('hex');
            const category = file.split('_')[0].toLowerCase();
            const secureImage: SecureImage = { id, originalFile: file, category };
            imageMap.set(id, secureImage);
            allImages.push(secureImage);
            imageIds.push(id);

            // Store mapping in Redis
            await RedisStore.setImageMapping(id, { file, category, sessionId });
        }

        // Store session data in Redis with explicit targetCategory
        await RedisStore.setSessionImages(sessionId, imageMap, targetCategory);

        // Shuffle all images for display
        const shuffledAll = this.shuffleArray(allImages);

        // Calculate valid answer IDs
        const validAnswerIds = selectedCorrect.map(file => {
            const found = allImages.find(img => img.originalFile === file);
            return found?.id || '';
        }).filter(id => id !== '');

        const challenge: SecureChallenge = {
            sessionId,
            question: `Select all images containing a ${targetCategory}`,
            imageIds: shuffledAll.map(img => img.id),
            validAnswerIds,
            targetCategory,  // FIXED: Stored explicitly
            createdAt: now,
            expiresAt: now + 5 * 60 * 1000,
        };

        return challenge;
    }

    /**
     * Serve an image by its random ID with transformations to prevent fingerprinting
     */
    async serveImage(imageId: string): Promise<Buffer | null> {
        const mapping = await RedisStore.getImageMapping(imageId);
        if (!mapping) {
            return null;
        }

        const filePath = path.join(this.imagesDir, mapping.file);
        if (!fs.existsSync(filePath)) {
            return null;
        }

        try {
            // Apply security transformations to prevent fingerprinting
            const image = sharp(filePath);

            // 1. Resize to standard dimensions (normalize sizes)
            // 2. Fixed quality to ensure consistent file sizes
            // 3. Strip all metadata (EXIF, etc.)
            const processed = await image
                .resize(200, 200, { fit: 'cover' })
                .jpeg({ quality: 80, chromaSubsampling: '4:4:4' })
                .rotate(0) // Force metadata strip
                .toBuffer();

            return processed;
        } catch (error) {
            console.error('Error processing image:', error);
            return null;
        }
    }

    /**
     * Serve image with additional noise for extra security
     */
    async serveImageWithNoise(imageId: string): Promise<Buffer | null> {
        const mapping = await RedisStore.getImageMapping(imageId);
        if (!mapping) {
            return null;
        }

        const filePath = path.join(this.imagesDir, mapping.file);
        if (!fs.existsSync(filePath)) {
            return null;
        }

        try {
            // Add random subtle modifications
            const rotate = (Math.random() - 0.5) * 2; // -1 to +1 degree
            const brightness = 1 + (Math.random() - 0.5) * 0.05; // 0.975 to 1.025

            const processed = await sharp(filePath)
                .resize(200, 200, { fit: 'cover' })
                .rotate(rotate) // Slight random rotation
                .modulate({ brightness }) // Slight brightness change
                .jpeg({ quality: 80, chromaSubsampling: '4:4:4' }) // Fixed quality for consistency
                .toBuffer();

            return processed;
        } catch (error) {
            console.error('Error processing image with noise:', error);
            return null;
        }
    }

    /**
     * Verify answers using secure IDs
     * FIXED: Uses stored targetCategory from Redis instead of recalculating
     */
    async verifyAnswers(sessionId: string, selectedIds: string[]): Promise<{
        correct: boolean;
        message: string;
    }> {
        const sessionData = await RedisStore.getSessionImages(sessionId);
        if (!sessionData) {
            return { correct: false, message: 'Session expired or invalid' };
        }

        const { images: session, targetCategory } = sessionData;

        // FIXED: Use stored targetCategory instead of recalculating
        if (!targetCategory) {
            return { correct: false, message: 'Invalid session data' };
        }

        // Get correct answers for this session using stored targetCategory
        const correctIds = new Set<string>();
        session.forEach((img, id) => {
            if (img.category === targetCategory) {
                correctIds.add(id);
            }
        });

        // Check if selected answers match
        const selected = new Set(selectedIds);
        const missed = [...correctIds].filter(id => !selected.has(id));
        const extra = [...selected].filter(id => !correctIds.has(id));

        if (missed.length === 0 && extra.length === 0) {
            await this.cleanupSession(sessionId, session);
            return { correct: true, message: 'Correct!' };
        }

        return {
            correct: false,
            message: 'Incorrect selection. Please try again.'
        };
    }

    /**
     * Cleanup session data from Redis
     */
    private async cleanupSession(sessionId: string, session?: Map<string, SecureImage>): Promise<void> {
        // Get session if not provided
        if (!session) {
            const sessionData = await RedisStore.getSessionImages(sessionId);
            if (sessionData) {
                session = sessionData.images;
            }
        }

        // Delete image mappings
        if (session) {
            const imageIds = Array.from(session.keys());
            await RedisStore.deleteImageMappingsBatch(imageIds);
        }

        // Delete session
        await RedisStore.deleteSessionImages(sessionId);
    }

    /**
     * Shuffle array
     */
    private shuffleArray<T>(array: T[]): T[] {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    }
}

// Also export a middleware for Express
export function createSecureImageMiddleware(secureServer: SecureImageServer) {
    return async (req: any, res: any, next: any) => {
        const imageId = req.params.imageId;

        if (!imageId) {
            return res.status(400).json({ error: 'Image ID required' });
        }

        const imageBuffer = await secureServer.serveImageWithNoise(imageId);

        if (!imageBuffer) {
            return res.status(404).json({ error: 'Image not found' });
        }

        // Set security headers
        res.set({
            'Content-Type': 'image/jpeg',
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0',
            // Prevent caching by adding random ETag
            'ETag': crypto.randomBytes(8).toString('hex'),
        });

        res.send(imageBuffer);
    };
}
