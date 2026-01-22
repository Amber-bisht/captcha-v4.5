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
            // SECURITY FIX P2.2: Randomize expiration (4-6 minutes)
            expiresAt: Date.now() + Math.ceil((4 + Math.random() * 2) * 60 * 1000)
        };
    }

    /**
     * Generates recognizable SVG objects that are easy for humans to orient
     * but still challenging for bots due to random colors and variations
     */
    private generateComplexShape(): string {
        const generateRandomColor = () => {
            const h = Math.floor(Math.random() * 360);
            const s = 60 + Math.floor(Math.random() * 40);
            const l = 45 + Math.floor(Math.random() * 25);
            return `hsl(${h}, ${s}%, ${l}%)`;
        };

        const color1 = generateRandomColor();
        const color2 = generateRandomColor();
        const color3 = generateRandomColor();
        const cx = this.frameSize / 2;
        const cy = this.frameSize / 2;

        // Choose a random recognizable object
        const objects = ['umbrella', 'cup', 'house', 'tree', 'rocket', 'boat', 'key', 'lightbulb', 'arrow', 'diamond'];
        const objectType = objects[Math.floor(Math.random() * objects.length)];

        let svg = `<svg width="${this.frameSize}" height="${this.frameSize}" xmlns="http://www.w3.org/2000/svg">`;
        svg += `<defs>
            <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:${color1};stop-opacity:1" />
                <stop offset="100%" style="stop-color:${color2};stop-opacity:1" />
            </linearGradient>
            <linearGradient id="grad2" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" style="stop-color:${color2};stop-opacity:1" />
                <stop offset="100%" style="stop-color:${color3};stop-opacity:1" />
            </linearGradient>
        </defs>`;

        switch (objectType) {
            case 'umbrella':
                // Umbrella - clearly upright when handle is at bottom
                svg += `<path d="M ${cx} 30 
                         Q ${cx - 50} 35 ${cx - 50} 65 
                         L ${cx + 50} 65 
                         Q ${cx + 50} 35 ${cx} 30 Z" 
                         fill="url(#grad1)" stroke="${color3}" stroke-width="3"/>`;
                svg += `<line x1="${cx}" y1="65" x2="${cx}" y2="115" stroke="${color3}" stroke-width="4"/>`;
                svg += `<path d="M ${cx} 115 Q ${cx + 15} 115 ${cx + 15} 125 Q ${cx + 15} 135 ${cx + 5} 135" 
                         fill="none" stroke="${color3}" stroke-width="4"/>`;
                break;

            case 'cup':
                // Coffee cup with steam
                svg += `<rect x="${cx - 25}" y="55" width="50" height="60" rx="5" fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<path d="M ${cx + 25} 65 Q ${cx + 45} 70 ${cx + 45} 85 Q ${cx + 45} 100 ${cx + 25} 105" 
                         fill="none" stroke="${color3}" stroke-width="4"/>`;
                // Steam
                svg += `<path d="M ${cx - 10} 55 Q ${cx - 15} 40 ${cx - 10} 30" fill="none" stroke="${color2}" stroke-width="2"/>`;
                svg += `<path d="M ${cx} 55 Q ${cx + 5} 35 ${cx} 25" fill="none" stroke="${color2}" stroke-width="2"/>`;
                svg += `<path d="M ${cx + 10} 55 Q ${cx + 15} 40 ${cx + 10} 30" fill="none" stroke="${color2}" stroke-width="2"/>`;
                break;

            case 'house':
                // Simple house
                svg += `<polygon points="${cx},25 ${cx - 45},60 ${cx + 45},60" fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<rect x="${cx - 35}" y="60" width="70" height="60" fill="url(#grad2)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<rect x="${cx - 12}" y="85" width="24" height="35" fill="${color1}" stroke="${color3}" stroke-width="2"/>`;
                svg += `<circle cx="${cx + 8}" cy="103" r="3" fill="${color3}"/>`;
                break;

            case 'tree':
                // Pine tree
                svg += `<polygon points="${cx},20 ${cx - 40},70 ${cx + 40},70" fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<polygon points="${cx},45 ${cx - 35},90 ${cx + 35},90" fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<polygon points="${cx},70 ${cx - 30},110 ${cx + 30},110" fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<rect x="${cx - 10}" y="110" width="20" height="25" fill="#8B4513" stroke="${color3}" stroke-width="2"/>`;
                break;

            case 'rocket':
                // Rocket ship
                svg += `<ellipse cx="${cx}" cy="60" rx="20" ry="40" fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<polygon points="${cx},20 ${cx - 15},45 ${cx + 15},45" fill="${color2}" stroke="${color3}" stroke-width="2"/>`;
                svg += `<polygon points="${cx - 20},85 ${cx - 35},115 ${cx - 15},100" fill="${color3}" stroke="${color3}" stroke-width="1"/>`;
                svg += `<polygon points="${cx + 20},85 ${cx + 35},115 ${cx + 15},100" fill="${color3}" stroke="${color3}" stroke-width="1"/>`;
                svg += `<ellipse cx="${cx}" cy="115" rx="12" ry="8" fill="#FF4500"/>`;
                svg += `<circle cx="${cx}" cy="55" r="8" fill="${color2}" stroke="white" stroke-width="2"/>`;
                break;

            case 'boat':
                // Sailboat
                svg += `<polygon points="${cx},25 ${cx},100 ${cx + 40},100" fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<line x1="${cx}" y1="25" x2="${cx}" y2="110" stroke="${color3}" stroke-width="3"/>`;
                svg += `<path d="M ${cx - 45} 110 Q ${cx - 30} 130 ${cx} 130 Q ${cx + 30} 130 ${cx + 45} 110 Z" 
                         fill="url(#grad2)" stroke="${color3}" stroke-width="2"/>`;
                break;

            case 'key':
                // Key shape
                svg += `<circle cx="${cx}" cy="40" r="20" fill="none" stroke="url(#grad1)" stroke-width="8"/>`;
                svg += `<rect x="${cx - 4}" y="55" width="8" height="60" fill="url(#grad1)" stroke="${color3}" stroke-width="1"/>`;
                svg += `<rect x="${cx}" y="95" width="15" height="6" fill="url(#grad1)" stroke="${color3}" stroke-width="1"/>`;
                svg += `<rect x="${cx}" y="105" width="10" height="6" fill="url(#grad1)" stroke="${color3}" stroke-width="1"/>`;
                break;

            case 'lightbulb':
                // Light bulb
                svg += `<ellipse cx="${cx}" cy="55" rx="30" ry="35" fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<path d="M ${cx - 15} 85 Q ${cx - 15} 100 ${cx - 10} 105 L ${cx + 10} 105 Q ${cx + 15} 100 ${cx + 15} 85" 
                         fill="${color2}" stroke="${color3}" stroke-width="2"/>`;
                svg += `<rect x="${cx - 10}" y="105" width="20" height="20" fill="${color3}" stroke="${color3}" stroke-width="1"/>`;
                // Filament lines
                svg += `<path d="M ${cx - 8} 50 Q ${cx} 60 ${cx + 8} 50" fill="none" stroke="${color3}" stroke-width="2"/>`;
                break;

            case 'arrow':
                // Upward arrow
                svg += `<polygon points="${cx},20 ${cx - 35},70 ${cx - 15},70 ${cx - 15},130 ${cx + 15},130 ${cx + 15},70 ${cx + 35},70" 
                         fill="url(#grad1)" stroke="${color3}" stroke-width="3"/>`;
                break;

            case 'diamond':
                // Diamond/gem shape
                svg += `<polygon points="${cx},25 ${cx + 40},55 ${cx + 30},60 ${cx - 30},60 ${cx - 40},55" 
                         fill="${color2}" stroke="${color3}" stroke-width="2"/>`;
                svg += `<polygon points="${cx + 30},60 ${cx - 30},60 ${cx},130" 
                         fill="url(#grad1)" stroke="${color3}" stroke-width="2"/>`;
                svg += `<line x1="${cx}" y1="60" x2="${cx}" y2="130" stroke="${color3}" stroke-width="1"/>`;
                svg += `<line x1="${cx - 15}" y1="60" x2="${cx}" y2="130" stroke="${color3}" stroke-width="1"/>`;
                svg += `<line x1="${cx + 15}" y1="60" x2="${cx}" y2="130" stroke="${color3}" stroke-width="1"/>`;
                break;
        }

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
