import { SpatialCaptchaGenerator } from '../utils/spatialCaptcha';
import * as fs from 'fs';
import * as path from 'path';

async function generateSample() {
    console.log('Generating sample spatial captcha...');

    const generator = new SpatialCaptchaGenerator();
    const challenge = await generator.generate();

    // Save the sprite sheet as PNG
    const outputPath = path.join(__dirname, '../../sample_captcha.png');
    fs.writeFileSync(outputPath, challenge.spriteSheet);

    console.log(`✅ Sample captcha saved to: ${outputPath}`);
    console.log(`   Total frames: ${challenge.totalFrames}`);
    console.log(`   Start frame: ${challenge.startFrame}`);
    console.log(`   Target frame (upright): ${challenge.targetFrame}`);
}

generateSample().catch(console.error);
