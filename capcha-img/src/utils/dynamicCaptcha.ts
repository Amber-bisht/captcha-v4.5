import sharp from 'sharp';
import crypto from 'crypto';
import * as svgCaptcha from 'svg-captcha';

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
     * Generate a challenge using Path-Based rendering (Server-Independent)
     */
    async generate(): Promise<CaptchaResult> {
        const id = crypto.randomBytes(16).toString('hex');

        // Use svg-captcha to generate the RAW SVG (Text-to-Path)
        // This ensures text ALWAYS shows up regardless of server fonts
        const captcha = svgCaptcha.create({
            size: 5,
            noise: 3,
            color: true,
            background: '#151515',
            width: this.width,
            height: this.height,
            fontSize: 60
        });

        const answer = captcha.data; // The text answer
        const rawSvg = captcha.data; // The SVG string (Wait, svgCaptcha.create returns {data, text})

        // Correction: svg-captcha returns {data: string (svg), text: string (answer)}
        const finalAnswer = captcha.text;
        const svgString = captcha.data;

        // Now use Sharp to apply your Premium Styling over the path-based SVG
        const image = await this.applyPremiumStyling(svgString);

        return {
            id,
            answer: finalAnswer,
            image,
            // SECURITY FIX P2.2: Randomize expiration (4-6 minutes)
            expiresAt: Date.now() + Math.ceil((4 + Math.random() * 2) * 60 * 1000)
        };
    }

    private async applyPremiumStyling(svgString: string): Promise<Buffer> {
        // We take the path-based SVG and apply post-processing for a premium look
        return sharp(Buffer.from(svgString))
            .ensureAlpha()
            .modulate({
                brightness: 1.2,
                saturation: 1.0
            })
            // Force a dark-mode background layer
            .flatten({ background: '#0a0a0a' })
            .jpeg({
                quality: 100,
                chromaSubsampling: '4:4:4'
            })
            .toBuffer();
    }
}
