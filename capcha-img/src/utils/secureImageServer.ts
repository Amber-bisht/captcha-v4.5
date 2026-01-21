/**
 * Secure Image Serving System
 * Prevents image CAPTCHA bypass through filename/size/metadata analysis
 * 
 * UPDATED: Uses Redis for storage instead of in-memory Maps
 * FIXED: Stores targetCategory explicitly to prevent multi-user bugs
 * ENHANCED: Aggressive image degradation to defeat ML classifiers
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
    difficulty: 'easy' | 'standard' | 'hard' | 'extreme';
    createdAt: number;
    expiresAt: number;
}

export interface ChallengeOptions {
    gridSize: number;
    difficulty: 'easy' | 'standard' | 'hard' | 'extreme';
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
     * Get category count for validation
     */
    public getCategoryCount(): number {
        return this.categories.size;
    }

    /**
     * Generate a secure challenge with randomized image IDs
     * FIXED: Now stores targetCategory explicitly in Redis
     */
    async generateSecureChallenge(options: ChallengeOptions = { gridSize: 9, difficulty: 'standard' }): Promise<SecureChallenge | null> {
        const { gridSize, difficulty } = options;
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

        // Select 2-4 correct images based on difficulty
        let minCorrect = 2;
        let maxCorrect = 4;
        if (difficulty === 'hard' || difficulty === 'extreme') {
            minCorrect = 3;
            maxCorrect = 5;
        }

        const numCorrect = Math.min(
            Math.floor(Math.random() * (maxCorrect - minCorrect + 1)) + minCorrect,
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

        for (const file of [...selectedCorrect, ...selectedDistractors]) {
            const id = crypto.randomBytes(8).toString('hex');
            const category = file.split('_')[0].toLowerCase();
            const secureImage: SecureImage = { id, originalFile: file, category };
            imageMap.set(id, secureImage);
            allImages.push(secureImage);

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
            difficulty,
            createdAt: now,
            expiresAt: now + 5 * 60 * 1000,
        };

        return challenge;
    }

    /**
     * Serve an image by its random ID with basic transformations
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
            const processed = await sharp(filePath)
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
     * Serve image with AGGRESSIVE degradation to defeat ML classifiers
     * Makes images harder for bots but still human-readable
     */
    async serveImageWithNoise(imageId: string, difficulty: 'easy' | 'standard' | 'hard' | 'extreme' = 'standard'): Promise<Buffer | null> {
        const mapping = await RedisStore.getImageMapping(imageId);
        if (!mapping) {
            return null;
        }

        const filePath = path.join(this.imagesDir, mapping.file);
        if (!fs.existsSync(filePath)) {
            return null;
        }

        try {
            // Get degradation settings based on difficulty
            const settings = this.getDegradationSettings(difficulty);

            // Start with the image
            let pipeline = sharp(filePath)
                .resize(200, 200, { fit: 'cover' });

            // Apply random rotation
            if (settings.maxRotation > 0) {
                const rotation = (Math.random() - 0.5) * 2 * settings.maxRotation;
                pipeline = pipeline.rotate(rotation);
            }

            // Apply color/brightness modifications
            pipeline = pipeline.modulate({
                brightness: settings.brightness + (Math.random() - 0.5) * 0.15,
                saturation: settings.saturation + (Math.random() - 0.5) * 0.3,
                hue: Math.floor(Math.random() * settings.hueShift)
            });

            // Apply blur for harder difficulties
            if (settings.blur > 0 && Math.random() > 0.4) {
                pipeline = pipeline.blur(settings.blur);
            }

            // Apply gamma correction (makes it slightly washed out/dark)
            if (settings.applyGamma) {
                pipeline = pipeline.gamma(1.5 + Math.random() * 0.5);
            }

            // Compress with varying quality (creates JPEG artifacts)
            const quality = settings.jpegQualityMin +
                Math.floor(Math.random() * (settings.jpegQualityMax - settings.jpegQualityMin));

            const processed = await pipeline
                .jpeg({
                    quality,
                    chromaSubsampling: settings.chromaSubsampling,
                    mozjpeg: true  // Better compression, more artifacts
                })
                .toBuffer();

            return processed;
        } catch (error) {
            console.error('Error processing image with noise:', error);
            return null;
        }
    }

    /**
     * Get degradation settings based on difficulty level
     */
    private getDegradationSettings(difficulty: 'easy' | 'standard' | 'hard' | 'extreme') {
        const settings = {
            easy: {
                maxRotation: 2,
                brightness: 1.0,
                saturation: 1.0,
                hueShift: 5,
                blur: 0,
                applyGamma: false,
                jpegQualityMin: 70,
                jpegQualityMax: 85,
                chromaSubsampling: '4:4:4' as const
            },
            standard: {
                maxRotation: 5,
                brightness: 0.95,
                saturation: 0.9,
                hueShift: 15,
                blur: 0.3,
                applyGamma: false,
                jpegQualityMin: 50,
                jpegQualityMax: 70,
                chromaSubsampling: '4:2:2' as const
            },
            hard: {
                maxRotation: 8,
                brightness: 0.85,
                saturation: 0.8,
                hueShift: 25,
                blur: 0.6,
                applyGamma: true,
                jpegQualityMin: 35,
                jpegQualityMax: 55,
                chromaSubsampling: '4:2:0' as const
            },
            extreme: {
                maxRotation: 12,
                brightness: 0.75,
                saturation: 0.7,
                hueShift: 40,
                blur: 1.0,
                applyGamma: true,
                jpegQualityMin: 25,
                jpegQualityMax: 40,
                chromaSubsampling: '4:2:0' as const
            }
        };

        return settings[difficulty];
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
     * Shuffle array using Fisher-Yates algorithm
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

// Express middleware for serving images
export function createSecureImageMiddleware(secureServer: SecureImageServer, difficulty: 'easy' | 'standard' | 'hard' | 'extreme' = 'standard') {
    return async (req: any, res: any, next: any) => {
        const imageId = req.params.imageId;

        if (!imageId) {
            return res.status(400).json({ error: 'Image ID required' });
        }

        const imageBuffer = await secureServer.serveImageWithNoise(imageId, difficulty);

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
