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
     * Hardened for bots, but high-quality for humans
     */
    async generate(): Promise<CaptchaResult> {
        const id = crypto.randomBytes(16).toString('hex');

        const isMath = Math.random() > 0.4;
        let answer = '';
        let textToShow = '';

        if (isMath) {
            const a = Math.floor(Math.random() * 40) + 10;
            const b = Math.floor(Math.random() * 20) + 5;
            const op = Math.random() > 0.5 ? '+' : '-';
            const res = op === '+' ? (a + b) : (a - b);
            answer = res.toString();
            textToShow = `${a}${op}${b}=`;
        } else {
            const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
            const length = 5;
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
        const bgColor = this.getRandomColor(15, 30);
        const textColor = '#FFFFFF';

        let svgContent = `<svg width="${this.width}" height="${this.height}" xmlns="http://www.w3.org/2000/svg">`;

        // Premium Dark Gradient
        svgContent += `
            <defs>
                <linearGradient id="premiumGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:${bgColor};stop-opacity:1" />
                    <stop offset="50%" style="stop-color:#0a0a0a;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:${this.getRandomColor(10, 40)};stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect width="100%" height="100%" fill="url(#premiumGrad)" />
        `;

        // Subtle elegant noise (Small dots)
        for (let i = 0; i < 40; i++) {
            const x = Math.random() * this.width;
            const y = Math.random() * this.height;
            svgContent += `<circle cx="${x}" cy="${y}" r="0.8" fill="white" fill-opacity="0.2" />`;
        }

        const charArray = text.split('');
        const step = (this.width - 60) / charArray.length;

        charArray.forEach((char, i) => {
            const fonts = ['Arial', 'Verdana', 'Georgia', 'Trebuchet MS'];
            const font = fonts[Math.floor(Math.random() * fonts.length)];
            const fontSize = 44 + Math.random() * 6;
            const fontWeight = '900';
            const rotation = Math.floor(Math.random() * 40) - 20;
            const offsetY = Math.floor(Math.random() * 12) - 6;
            const offsetX = 35 + (i * step);

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

        // Anti-OCR lines (Thin & Sharp)
        for (let i = 0; i < 4; i++) {
            const y1 = Math.random() * this.height;
            const y2 = Math.random() * this.height;
            svgContent += `<line x1="0" y1="${y1}" x2="${this.width}" y2="${y2}" stroke="white" stroke-opacity="0.3" stroke-width="1.2" />`;
        }

        svgContent += '</svg>';
        return svgContent;
    }

    private async applyPostProcessing(svg: string): Promise<Buffer> {
        return sharp(Buffer.from(svg))
            .jpeg({
                quality: 100, // Maximum Quality to avoid artifacts
                chromaSubsampling: '4:4:4' // Professional color sharpnes
            })
            .toBuffer();
    }

    private getRandomColor(min: number, max: number): string {
        const r = Math.floor(Math.random() * (max - min) + min);
        const g = Math.floor(Math.random() * (max - min) + min);
        const b = Math.floor(Math.random() * (max - min) + min);
        return `rgb(${r},${g},${b})`;
    }
}
