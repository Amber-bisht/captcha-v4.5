import { DynamicCaptchaGenerator } from './src/utils/dynamicCaptcha';
import fs from 'fs';
import path from 'path';

async function generateSample() {
    console.log('🚀 Generating High-Quality Test Captcha...');
    const generator = new DynamicCaptchaGenerator();

    try {
        const result = await generator.generate();

        const outputPath = path.join(__dirname, 'sample_captcha.jpg');
        fs.writeFileSync(outputPath, result.image);

        const stats = fs.statSync(outputPath);

        console.log('\n✅ TEST SUCCESSFUL!');
        console.log(`- Answer: ${result.answer}`);
        console.log(`- File size: ${stats.size} bytes`);
        console.log(`- Saved to: ${outputPath}`);

        if (stats.size < 5000) {
            console.warn('\n⚠️  WARNING: File size is very small! The image might be empty/blank.');
        } else {
            console.log('\n✨ Quality check passed. Please open the image to verify clarity.');
        }
    } catch (err) {
        console.error('\n❌ GENERATION FAILED!');
        console.error(err);
        process.exit(1);
    }
}

generateSample();
