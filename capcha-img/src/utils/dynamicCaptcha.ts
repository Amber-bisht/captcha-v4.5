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
     * Generate a challenge based on the 20-Factor Dynamic System (Balanced for human & bot)
     */
    async generate(): Promise<CaptchaResult> {
        const id = crypto.randomBytes(16).toString('hex');

        const isMath = Math.random() > 0.4; // 60% chance of math for complexity
        let answer = '';
        let textToShow = '';

        if (isMath) {
            const a = Math.floor(Math.random() * 30) + 5;
            const b = Math.floor(Math.random() * 20) + 2;
            const op = Math.random() > 0.5 ? '+' : '-';
            const res = op === '+' ? (a + b) : (a - b);
            answer = res.toString();
            textToShow = `${a}${op}${b}=`;
        } else {
            const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
            const length = Math.floor(Math.random() * 2) + 5; // 5-6 characters
            for (let i = 0; i < length; i++) {
                answer += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            textToShow = answer;
        }

        const svg = this.generateSVG(textToShow);
        const image = await this.applyPostProcessing(svg);

        return {
            id,
            answer,
            image,
            expiresAt: Date.now() + 5 * 60 * 1000
        };
    }

    private generateSVG(text: string): string {
        const bgColor1 = this.getRandomColor(10, 40);
        const bgColor2 = this.getRandomColor(10, 40);
        const textColor = this.getRandomColor(200, 255); // Variations of off-white

        let svgContent = `<svg width="${this.width}" height="${this.height}" xmlns="http://www.w3.org/2000/svg">`;
        svgContent += `
            <defs>
                <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:${bgColor1};stop-opacity:1" />
                    <stop offset="100%" style="stop-color:${bgColor2};stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect width="100%" height="100%" fill="url(#bgGrad)" />
        `;

        // Background interference shapes
        for (let i = 0; i < 8; i++) {
            const x = Math.random() * this.width;
            const y = Math.random() * this.height;
            const size = Math.random() * 30 + 5;
            svgContent += `<circle cx="${x}" cy="${y}" r="${size / 2}" fill="${textColor}" fill-opacity="0.15" />`;
        }

        const charArray = text.split('');
        const step = (this.width - 60) / charArray.length;

        charArray.forEach((char, i) => {
            const fonts = ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia'];
            const font = fonts[Math.floor(Math.random() * fonts.length)];
            const fontSize = Math.floor(Math.random() * 10) + 40;
            const fontWeight = '800';
            const rotation = Math.floor(Math.random() * 50) - 25; // Re-introduced moderate rotation
            const offsetY = Math.floor(Math.random() * 16) - 8;
            const offsetX = 30 + (i * step) + (Math.random() * 10 - 5);

            svgContent += `
                <text 
                    x="${offsetX}" 
                    y="${this.height / 2 + 10 + offsetY}" 
                    font-family="${font}" 
                    font-size="${fontSize}" 
                    font-weight="${fontWeight}" 
                    fill="${textColor}"
                    transform="rotate(${rotation}, ${offsetX}, ${this.height / 2})"
                    style="dominant-baseline: middle; text-anchor: middle;"
                >${char}</text>
            `;
        });

        // Cutting lines (Interference)
        for (let i = 0; i < 5; i++) {
            const y1 = Math.random() * this.height;
            const y2 = Math.random() * this.height;
            svgContent += `<line x1="0" y1="${y1}" x2="${this.width}" y2="${y2}" stroke="${textColor}" stroke-opacity="0.4" stroke-width="1.5" />`;
        }

        svgContent += '</svg>';
        return svgContent;
    }

    private async applyPostProcessing(svg: string): Promise<Buffer> {
        let pipeline = sharp(Buffer.from(svg));

        // Add very light blur to soften edges (makes OCR harder)
        pipeline = pipeline.blur(0.4);

        return pipeline
            .affine([[1, 0.03], [0.03, 1]], { background: '#000000' }) // Very slight perspective warp
            .jpeg({ quality: 85 })
            .toBuffer();
    }

    private getRandomColor(min: number, max: number): string {
        const r = Math.floor(Math.random() * (max - min) + min);
        const g = Math.floor(Math.random() * (max - min) + min);
        const b = Math.floor(Math.random() * (max - min) + min);
        return `rgb(${r},${g},${b})`;
    }
}
