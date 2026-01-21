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

    async generate(): Promise<CaptchaResult> {
        const id = crypto.randomBytes(16).toString('hex');
        const isMath = Math.random() > 0.4;
        let answer = '';
        let textToShow = '';

        if (isMath) {
            const a = Math.floor(Math.random() * 40) + 10;
            const b = Math.floor(Math.random() * 20) + 5;
            const op = Math.random() > 0.5 ? '+' : '-';
            answer = (op === '+' ? (a + b) : (a - b)).toString();
            textToShow = `${a}${op}${b}=`;
        } else {
            const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
            for (let i = 0; i < 5; i++) {
                answer += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            textToShow = answer;
        }

        const svg = this.generateSVG(textToShow);
        const image = await this.applyPostProcessing(svg);

        // EXTRA SECURITY: If image is suspiciously small (e.g. < 5KB), it means text failed to render
        if (!image || image.length < 5000) {
            console.error('❌ CAPTCHA Error: Image rendering returned suspicious empty buffer.');
            throw new Error('CAPTCHA_GENERATION_FAILED');
        }

        return { id, answer, image, expiresAt: Date.now() + 5 * 60 * 1000 };
    }

    private generateSVG(text: string): string {
        const bgColor = this.getRandomColor(10, 25);
        const textColor = '#FFFFFF';

        // Bulletproof SVG: No complex transforms on the <text> element itself
        // Instead, we use simple positioning and basic font fallbacks
        let svgContent = `<svg width="${this.width}" height="${this.height}" viewBox="0 0 ${this.width} ${this.height}" xmlns="http://www.w3.org/2000/svg">`;
        svgContent += `<rect width="100%" height="100%" fill="${bgColor}" opacity="1" />`;

        // Background dots
        for (let i = 0; i < 40; i++) {
            svgContent += `<circle cx="${Math.random() * this.width}" cy="${Math.random() * this.height}" r="1.2" fill="white" fill-opacity="0.2" />`;
        }

        const charArray = text.split('');
        const totalSpacing = this.width - 60;
        const charStep = totalSpacing / charArray.length;

        charArray.forEach((char, i) => {
            const x = 30 + (i * charStep) + (Math.random() * 10 - 5);
            const y = this.height / 2 + 15;
            const rotate = Math.floor(Math.random() * 40) - 20;

            // Using multiple font fallbacks to handle environment differences
            svgContent += `
                <text 
                    x="${x}" 
                    y="${y}" 
                    fill="${textColor}" 
                    font-size="52" 
                    font-weight="900" 
                    font-family="DejaVu Sans, Bitstream Vera Sans, Arial, Helvetica, sans-serif"
                    transform="rotate(${rotate}, ${x}, ${y})"
                    text-anchor="middle"
                >${char}</text>
            `;
        });

        // 3 Interference lines
        for (let i = 0; i < 3; i++) {
            svgContent += `<line x1="0" y1="${Math.random() * this.height}" x2="${this.width}" y2="${Math.random() * this.height}" stroke="white" stroke-opacity="0.3" stroke-width="2" />`;
        }

        svgContent += '</svg>';
        return svgContent;
    }

    private async applyPostProcessing(svg: string): Promise<Buffer> {
        return sharp(Buffer.from(svg))
            .flatten({ background: '#111111' }) // Ensure a solid background layer
            .png()
            .jpeg({ quality: 100 })
            .toBuffer();
    }

    private getRandomColor(min: number, max: number): string {
        const r = Math.floor(Math.random() * (max - min) + min);
        const g = Math.floor(Math.random() * (max - min) + min);
        const b = Math.floor(Math.random() * (max - min) + min);
        return `rgb(${r},${g},${b})`;
    }
}
