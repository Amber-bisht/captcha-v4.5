import crypto from 'crypto';
import sharp from 'sharp';
import RedisStore from './redisStore';

export interface SpatialChallenge {
    id: string;
    spriteSheet: Buffer; // One image containing 36 scrambled frames
    totalFrames: number;
    startFrame: number;  // The random starting frame index (0-35)
    targetFrame: number; // The frame index that is "upright"
    expiresAt: number;
}

export class SpatialCaptchaGenerator {
    private frameSize = 150; // Each frame is 150x150
    private totalFrames = 36; // 10 degree steps

    /**
     * Generate a Spatial (Rotation) Challenge
     * 1. Creates a unique, complex abstract shape
     * 2. Renders it at 36 different rotation angles
     * 3. Scrambles the order of frames in the sprite sheet
     * 4. Stores the 'correct' frame index in Redis
     */
    async generate(): Promise<SpatialChallenge> {
        const id = crypto.randomBytes(16).toString('hex');

        // Create a unique abstract shape for this challenge
        const baseSvg = this.generateComplexShape();
        const baseImage = await sharp(Buffer.from(baseSvg)).toBuffer();

        // Create 36 frames (rotated 0-350 degrees)
        const frames: { index: number; buffer: Buffer }[] = [];
        for (let i = 0; i < this.totalFrames; i++) {
            const angle = i * 10;
            const buffer = await sharp(baseImage)
                .rotate(angle, { background: { r: 0, g: 0, b: 0, alpha: 0 } })
                .resize(this.frameSize, this.frameSize)
                .png()
                .toBuffer();
            frames.push({ index: i, buffer });
        }

        // Target: We want the "Upright" position (angle 0, which is index 0)
        // But we SCRAMBLE the sprite sheet so the bot can't guess by position
        const scrambledFrames = this.shuffleArray([...frames]);
        const targetFrameIndex = scrambledFrames.findIndex(f => f.index === 0);
        const startFrameIndex = Math.floor(Math.random() * this.totalFrames);

        // Combine scrambled frames into a single sprite sheet (6x6 grid)
        const spriteSheet = await this.createGrid(scrambledFrames.map(f => f.buffer));

        return {
            id,
            spriteSheet,
            totalFrames: this.totalFrames,
            startFrame: startFrameIndex,
            targetFrame: targetFrameIndex,
            expiresAt: Date.now() + 5 * 60 * 1000
        };
    }

    /**
     * Generates a complex SVG shape that is hard for AI to "center" or "orient"
     * Uses random paths, gradients, and overlapping elements
     */
    private generateComplexShape(): string {
        const colors = [
            '#FF5733', '#33FF57', '#3357FF', '#F333FF',
            '#33FFF3', '#F3FF33', '#FF3380', '#80FF33'
        ];
        const color1 = colors[Math.floor(Math.random() * colors.length)];
        const color2 = colors[Math.floor(Math.random() * colors.length)];

        let svg = `<svg width="${this.frameSize}" height="${this.frameSize}" xmlns="http://www.w3.org/2000/svg">`;
        svg += `<defs><linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:${color1};stop-opacity:1" /><stop offset="100%" style="stop-color:${color2};stop-opacity:1" /></linearGradient></defs>`;

        // Add random complex paths
        for (let i = 0; i < 5; i++) {
            const d = `M ${Math.random() * this.frameSize} ${Math.random() * this.frameSize} 
                       Q ${Math.random() * this.frameSize} ${Math.random() * this.frameSize} 
                         ${Math.random() * this.frameSize} ${Math.random() * this.frameSize} 
                       T ${Math.random() * this.frameSize} ${Math.random() * this.frameSize}`;
            svg += `<path d="${d}" stroke="url(#grad)" fill="none" stroke-width="${Math.random() * 10 + 2}" />`;
        }

        // Add a "marker" that is recognizable to humans but ambiguous to bots
        const markerX = this.frameSize / 2;
        const markerY = 20; // Near the top
        svg += `<circle cx="${markerX}" cy="${markerY}" r="8" fill="white" stroke="black" stroke-width="2" />`;
        svg += `<path d="M ${markerX - 10} ${markerY + 10} L ${markerX} ${markerY} L ${markerX + 10} ${markerY + 10}" stroke="white" fill="none" stroke-width="3" />`;

        svg += `</svg>`;
        return svg;
    }

    /**
     * Combine frames into a single image grid
     */
    private async createGrid(frameBuffers: Buffer[]): Promise<Buffer> {
        const cols = 6;
        const rows = 6;

        const composites = frameBuffers.map((buffer, i) => ({
            input: buffer,
            top: Math.floor(i / cols) * this.frameSize,
            left: (i % cols) * this.frameSize,
        }));

        return sharp({
            create: {
                width: this.frameSize * cols,
                height: this.frameSize * rows,
                channels: 4,
                background: { r: 0, g: 0, b: 0, alpha: 0 }
            }
        })
            .composite(composites)
            .png()
            .toBuffer();
    }

    private shuffleArray<T>(array: T[]): T[] {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    }
}
