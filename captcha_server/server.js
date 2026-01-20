const express = require('express');
const session = require('express-session');
const svgCaptcha = require('svg-captcha');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
    secret: 'lab-secret-key', // In production, use a secure random string
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // secure: true for HTTPS
}));

// Route to get captcha
app.get('/captcha', (req, res) => {
    const captcha = svgCaptcha.create({
        size: 5, // length of captcha
        ignoreChars: '0o1i', // filter out some characters
        noise: 2, // number of noise lines
        color: true, // characters will have distinct colors
        background: '#cc9966' // background color
    });
    
    // Store captcha text in session
    req.session.captcha = captcha.text;
    
    // Return SVG image
    res.type('svg');
    res.status(200).send(captcha.data);
});

// Route to verify captcha
app.post('/verify', (req, res) => {
    const userCaptcha = req.body.captcha;
    
    if (!req.session.captcha) {
        return res.json({ success: false, message: 'Captcha expired or not generated.' });
    }

    if (!userCaptcha) {
        return res.json({ success: false, message: 'Please enter the captcha.' });
    }

    if (userCaptcha.toLowerCase() === req.session.captcha.toLowerCase()) {
        // Clear captcha after successful validation to prevent reuse
        req.session.captcha = null;
        return res.json({ success: true, message: 'Captcha matched! Success.' });
    } else {
        return res.json({ success: false, message: 'Incorrect captcha. Please try again.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
