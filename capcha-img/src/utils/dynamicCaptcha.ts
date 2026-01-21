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

        return { id, answer, image, expiresAt: Date.now() + 5 * 60 * 1000 };
    }

    private generateSVG(text: string): string {
        const bgColor = this.getRandomColor(10, 25);

        // Use a very high-contrast white
        const textColor = '#FFFFFF';

        let svgContent = `<svg width="${this.width}" height="${this.height}" xmlns="http://www.w3.org/2000/svg">`;
        svgContent += `<rect width="100%" height="100%" fill="${bgColor}" />`;

        // Background dots
        for (let i = 0; i < 50; i++) {
            svgContent += `<circle cx="${Math.random() * this.width}" cy="${Math.random() * this.height}" r="1" fill="white" fill-opacity="0.2" />`;
        }

        const charArray = text.split('');
        const step = (this.width - 60) / charArray.length;

        charArray.forEach((char, i) => {
            const fontSize = 46;
            const rotation = Math.floor(Math.random() * 30) - 15;
            const x = 40 + (i * step);
            const y = this.height / 2 + 10;

            // USE GENERIC SANS-SERIF TO ENSURE RENDERING ON ALL SYSTEMS
            svgContent += `
                <text 
                    x="${x}" 
                    y="${y}" 
                    font-family="sans-serif" 
                    font-size="${fontSize}" 
                    font-weight="bold" 
                    fill="${textColor}"
                    transform="rotate(${rotation}, ${x}, ${y})"
                    text-anchor="middle"
                >${char}</text>
            `;
        });

        // Interference lines
        for (let i = 0; i < 3; i++) {
            svgContent += `<line x1="0" y1="${Math.random() * this.height}" x2="${this.width}" y2="${Math.random() * this.height}" stroke="white" stroke-opacity="0.4" stroke-width="1.5" />`;
        }

        svgContent += '</svg>';
        return svgContent;
    }

    private async applyPostProcessing(svg: string): Promise<Buffer> {
        return sharp(Buffer.from(svg))
            .png() // PNG first for best clarity
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
