import { DynamicCaptchaGenerator } from './src/utils/dynamicCaptcha';
import fs from 'fs';
import path from 'path';

async function generateSample() {
    const generator = new DynamicCaptchaGenerator();
    const result = await generator.generate();

    const outputPath = path.join(__dirname, 'sample_captcha.jpg');
    fs.writeFileSync(outputPath, result.image);
    console.log(`Sample saved to: ${outputPath}`);
    console.log(`Answer should be: ${result.answer}`);
}

generateSample().catch(console.error);
