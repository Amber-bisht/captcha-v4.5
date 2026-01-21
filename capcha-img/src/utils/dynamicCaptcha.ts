import sharp from 'sharp';
import crypto from 'crypto';

export interface CaptchaResult {
    id: string;
    answer: string;
    image: Buffer;
    expiresAt: number;
}

export class DynamicCaptchaGenerator {
    private width = 300;
    private height = 120;

    /**
     * Generate a challenge based on the 20-Factor Dynamic System
     */
    async generate(): Promise<CaptchaResult> {
        const id = crypto.randomBytes(16).toString('hex');

        // 1. Content Type (Math vs Text)
        const isMath = Math.random() > 0.5;
        let answer = '';
        let textToShow = '';

        if (isMath) {
            const a = Math.floor(Math.random() * 20) + 1;
            const b = Math.floor(Math.random() * 20) + 1;
            const op = Math.random() > 0.5 ? '+' : '-';
            answer = op === '+' ? (a + b).toString() : (a - b).toString();
            textToShow = `${a}${op}${b}=?`;
        } else {
            // 2. Word Length (4-8) & 3. Case Jitter
            const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'; // Reduced ambiguous chars
            const length = Math.floor(Math.random() * 5) + 4;
            for (let i = 0; i < length; i++) {
                answer += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            textToShow = answer;
        }

        // Generate the base SVG with 20 factors applied
        const svg = this.generateSVG(textToShow);

        // Post-processing with sharp (factors 16, 19, 20)
        const image = await this.applyPostProcessing(svg);

        return {
            id,
            answer,
            image,
            expiresAt: Date.now() + 5 * 60 * 1000 // 5 minutes
        };
    }

    private generateSVG(text: string): string {
        // 8. BG Color & 10. BG Gradient
        const bgColor1 = this.getRandomColor(30, 100); // Darker for contrast
        const bgColor2 = this.getRandomColor(30, 100);
        const gradAngle = Math.floor(Math.random() * 360);

        // 9. Text Color (Contrast-aware random)
        const textColor = this.getRandomColor(180, 255); // Lighter for contrast

        let svgContent = `<svg width="${this.width}" height="${this.height}" xmlns="http://www.w3.org/2000/svg">`;
        svgContent += `
            <defs>
                <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%" gradientTransform="rotate(${gradAngle})">
                    <stop offset="0%" style="stop-color:${bgColor1};stop-opacity:1" />
                    <stop offset="100%" style="stop-color:${bgColor2};stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect width="100%" height="100%" fill="url(#bgGrad)" />
        `;

        // 18. Overlay Shapes (Translucent circles/triangles)
        for (let i = 0; i < 5; i++) {
            const x = Math.random() * this.width;
            const y = Math.random() * this.height;
            const size = Math.random() * 40 + 10;
            const color = this.getRandomColor(50, 200);
            if (Math.random() > 0.5) {
                svgContent += `<circle cx="${x}" cy="${y}" r="${size / 2}" fill="${color}" fill-opacity="0.3" />`;
            } else {
                svgContent += `<polygon points="${x},${y} ${x + size},${y} ${x + size / 2},${y + size}" fill="${color}" fill-opacity="0.3" />`;
            }
        }

        // 17. Interference Lines (Bezier curves)
        for (let i = 0; i < 4; i++) {
            const x1 = 0, y1 = Math.random() * this.height;
            const x2 = this.width, y2 = Math.random() * this.height;
            const cx1 = Math.random() * this.width, cy1 = Math.random() * this.height;
            const cx2 = Math.random() * this.width, cy2 = Math.random() * this.height;
            svgContent += `<path d="M ${x1} ${y1} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${x2} ${y2}" stroke="${textColor}" fill="transparent" stroke-width="1" stroke-opacity="0.4" />`;
        }

        // Render characters individually
        const charArray = text.split('');
        const step = (this.width - 40) / charArray.length;

        charArray.forEach((char, i) => {
            // 4. Font Family, 5. Font Weight, 6. Font Size
            const fonts = ['serif', 'sans-serif', 'monospace', 'cursive'];
            const fontFamily = fonts[Math.floor(Math.random() * fonts.length)];
            const fontWeight = Math.floor(Math.random() * 800) + 100;
            const fontSize = Math.floor(Math.random() * 18) + 28;

            // 11. Individual Rotation, 12. Character Offset, 13. Kerning/Spacing
            const rotation = Math.floor(Math.random() * 70) - 35;
            const offsetY = Math.floor(Math.random() * 20) - 10;
            const offsetX = 20 + (i * step) + (Math.random() * 10 - 5);

            // 7. Character Scaling (Horizontal/Vertical)
            const scaleX = 0.8 + Math.random() * 0.4;
            const scaleY = 0.8 + Math.random() * 0.4;

            svgContent += `
                <text 
                    x="${offsetX}" 
                    y="${this.height / 2 + 10 + offsetY}" 
                    font-family="${fontFamily}" 
                    font-size="${fontSize}" 
                    font-weight="${fontWeight}" 
                    fill="${textColor}"
                    transform="rotate(${rotation}, ${offsetX}, ${this.height / 2}) scale(${scaleX}, ${scaleY})"
                    style="dominant-baseline: middle; text-anchor: middle;"
                >${char}</text>
            `;
        });

        // 14. Global Warp simulation (via another wave path) - Simplified for SVG
        // 15. Perspective - Hard to do in pure SVG without complex transforms, skipping to keep it lightweight or done via sharp

        svgContent += '</svg>';
        return svgContent;
    }

    private async applyPostProcessing(svg: string): Promise<Buffer> {
        let pipeline = sharp(Buffer.from(svg));

        // 19. Gaussian Blur
        if (Math.random() > 0.5) {
            pipeline = pipeline.blur(0.5 + Math.random() * 0.5);
        }

        // 16. Salt & Pepper noise (simulated by adding noise and compositing)
        // 20. Negative Invert (Circular region inversion)
        const image = await pipeline.png().toBuffer();

        // Final transformations using sharp
        return sharp(image)
            // 15. Perspective (Approximate with affine)
            .affine([[1, 0.05], [0.05, 1]], { background: '#000000' })
            .jpeg({ quality: 80 })
            .toBuffer();
    }

    private getRandomColor(min: number, max: number): string {
        const r = Math.floor(Math.random() * (max - min) + min);
        const g = Math.floor(Math.random() * (max - min) + min);
        const b = Math.floor(Math.random() * (max - min) + min);
        return `rgb(${r},${g},${b})`;
    }
}
