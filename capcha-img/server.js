const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));


const sessionStore = new Map();


const getImageFiles = () => {
    const dir = path.join(__dirname, 'public', 'images');
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir).filter(file => {
        return /\.(jpg|jpeg|png|gif|webp)$/i.test(file);
    });
};

// Start a new Captcha Challenge
app.get('/api/captcha', (req, res) => {
    const files = getImageFiles();
    
    if (files.length === 0) {
        return res.status(500).json({ error: 'No images found on server.' });
    }

    // Extract categories from filenames (prefix before underscore)
    // Example: "dog_1.jpg" -> "dog"
    const categories = new Set();
    const headers = new Map(); // file -> category

    files.forEach(file => {
        const parts = file.split('_');
        if (parts.length > 1) {
            const category = parts[0].toLowerCase();
            categories.add(category);
            headers.set(file, category);
        }
    });

    if (categories.size === 0) {
        return res.status(500).json({ error: 'No valid categorized images found.' });
    }

    // Pick a random target category
    const categoryArray = Array.from(categories);
    const targetCategory = categoryArray[Math.floor(Math.random() * categoryArray.length)];

    // Select images
    const correctImages = files.filter(f => headers.get(f) === targetCategory);
    const otherImages = files.filter(f => headers.get(f) !== targetCategory);

    // We need 9 images total for a 3x3 grid (or fewer if not enough)
    // Let's aim for a mix. If we don't have enough total images, just send what we have.
    // Ideally we want at least 1 correct image.
    
    // Shuffle arrays
    const shuffle = (arr) => arr.sort(() => Math.random() - 0.5);
    
    let selectedImages = [];
    
    // Ensure at least one correct image if available
    if (correctImages.length > 0) {
        // Take up to 9 correct images
        selectedImages = selectedImages.concat(createSubset(correctImages, Math.min(correctImages.length, 5))); // Max 5 correct
    }
    
    // Fill the rest with distractors
    const remainingSlots = 9 - selectedImages.length;
    if (remainingSlots > 0 && otherImages.length > 0) {
        selectedImages = selectedImages.concat(createSubset(otherImages, remainingSlots));
    }
    
    // If still less than 9, maybe add more correct ones if we limited them before? 
    // For simplicity, just shuffle what we have.
    selectedImages = shuffle(selectedImages);

    // Create a Session ID
    const sessionId = Date.now().toString() + Math.random().toString(36).substring(2);
    
    sessionStore.set(sessionId, {
        targetCategory,
        // Store just the filenames of correct answers that are PRESENT in this grid
        // Not all correct images in existence, only the ones shown.
        validAnswers: selectedImages.filter(img => headers.get(img) === targetCategory)
    });

    res.json({
        sessionId,
        question: `Select all images containing a ${targetCategory}`,
        images: selectedImages
    });
});

function createSubset(arr, count) {
    const shuffled = arr.slice().sort(() => 0.5 - Math.random());
    return shuffled.slice(0, count);
}

// Verify Captcha
app.post('/api/verify', (req, res) => {
    const { sessionId, selectedImages } = req.body;

    if (!sessionStore.has(sessionId)) {
        return res.status(400).json({ success: false, message: 'Invalid or expired session' });
    }

    const session = sessionStore.get(sessionId);
    const expected = new Set(session.validAnswers);
    const received = new Set(selectedImages);

    // Logic: 
    // 1. Must select ALL correct images shown? Or just only correct ones?
    // Usually "Select all" means finding all of them.
    // Also must NOT select any incorrect ones.
    
    const missed = [...expected].filter(x => !received.has(x));
    const extra = [...received].filter(x => !expected.has(x));

    if (missed.length === 0 && extra.length === 0) {
        // Correct
        sessionStore.delete(sessionId); // Clear session to prevent replay
        res.json({ success: true, message: 'Captcha verified successfully!' });
    } else {
        res.json({ success: false, message: 'Incorrect selection. Please try again.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
