"use strict";
/**
 * Client-side script for image CAPTCHA
 */
const API_URL = '/api';
const captchaTriggerBtn = document.getElementById('captcha-trigger-btn');
const modal = document.getElementById('captcha-modal');
const grid = document.getElementById('captcha-grid');
const verifyBtn = document.getElementById('verify-captcha');
const refreshBtn = document.getElementById('refresh-captcha');
const instructionText = document.getElementById('captcha-instruction');
const statusMsg = document.getElementById('captcha-status');
const submitBtn = document.getElementById('submit-btn');
let currentSessionId = null;
let currentToken = null;
let currentCsrfToken = null;
let selectedImages = new Set();
// Open Modal
if (captchaTriggerBtn) {
    captchaTriggerBtn.addEventListener('click', () => {
        loadCaptcha();
        if (modal) {
            modal.classList.remove('hidden');
            setTimeout(() => modal.classList.add('visible'), 10);
        }
    });
}
// Close Modal (Click outside)
if (modal) {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });
}
function closeModal() {
    if (modal) {
        modal.classList.remove('visible');
        setTimeout(() => modal.classList.add('hidden'), 300);
    }
}
async function loadCaptcha() {
    if (!grid)
        return;
    grid.innerHTML = '<div style="grid-column: 1/-1; text-align: center;">Loading...</div>';
    selectedImages.clear();
    try {
        const response = await fetch(`${API_URL}/captcha`);
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Failed to load');
        }
        const data = await response.json();
        currentSessionId = data.sessionId;
        currentToken = data.token;
        currentCsrfToken = data.csrfToken;
        if (instructionText) {
            instructionText.textContent = data.question;
        }
        renderGrid(data.images);
    }
    catch (error) {
        if (grid) {
            grid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; color: red;">Error: ${error.message}<br>Make sure you have images in public/images/</div>`;
        }
    }
}
function renderGrid(images) {
    if (!grid)
        return;
    grid.innerHTML = '';
    images.forEach((imgName) => {
        const div = document.createElement('div');
        div.className = 'captcha-item';
        const img = document.createElement('img');
        img.src = `/images/${imgName}`;
        img.alt = 'captcha option';
        div.appendChild(img);
        div.addEventListener('click', () => {
            if (selectedImages.has(imgName)) {
                selectedImages.delete(imgName);
                div.classList.remove('selected');
            }
            else {
                selectedImages.add(imgName);
                div.classList.add('selected');
            }
        });
        grid.appendChild(div);
    });
}
if (verifyBtn) {
    verifyBtn.addEventListener('click', async () => {
        if (!currentSessionId || !currentToken || !currentCsrfToken)
            return;
        if (verifyBtn) {
            verifyBtn.textContent = 'Verifying...';
        }
        try {
            // Get behavior data (if behaviorTracker is loaded)
            const behaviorData = window.getBehaviorData ? window.getBehaviorData() : null;
            const response = await fetch(`${API_URL}/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': currentCsrfToken,
                },
                body: JSON.stringify({
                    sessionId: currentSessionId,
                    selectedImages: Array.from(selectedImages),
                    token: currentToken,
                    behaviorData,
                }),
            });
            const result = await response.json();
            if (result.success) {
                closeModal();
                if (captchaTriggerBtn) {
                    captchaTriggerBtn.style.display = 'none';
                }
                if (statusMsg) {
                    statusMsg.textContent = 'Verification Complete ✓';
                    statusMsg.className = 'status-msg success';
                }
                if (submitBtn) {
                    submitBtn.disabled = false;
                }
                // Clear tokens
                currentSessionId = null;
                currentToken = null;
                currentCsrfToken = null;
            }
            else {
                alert('Incorrect. Please try again.');
                loadCaptcha(); // Reload a fresh challenge
            }
        }
        catch (error) {
            console.error(error);
            alert('Verification failed due to a server error.');
        }
        finally {
            if (verifyBtn) {
                verifyBtn.textContent = 'Verify';
            }
        }
    });
}
if (refreshBtn) {
    refreshBtn.addEventListener('click', loadCaptcha);
}
