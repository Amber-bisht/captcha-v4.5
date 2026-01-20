/**
 * Client-side script for CAPTCHA verification
 */

let currentChallengeId: string | null = null;
let currentToken: string | null = null;
let currentCsrfToken: string | null = null;

// Fetch captcha on page load
window.onload = fetchCaptcha;

async function fetchCaptcha(): Promise<void> {
  const resultDiv = document.getElementById('result-message');
  if (resultDiv) {
    resultDiv.textContent = '';
  }
  const input = document.getElementById('captcha-input') as HTMLInputElement;
  if (input) {
    input.value = '';
  }

  try {
    const response = await fetch('/captcha');
    if (response.ok) {
      const svgData = await response.text();
      const captchaImg = document.getElementById('captcha-img');
      if (captchaImg) {
        captchaImg.innerHTML = svgData;
      }
      // Get challenge ID and token from response headers
      currentChallengeId = response.headers.get('X-Challenge-Id');
      currentToken = response.headers.get('X-Token');
      currentCsrfToken = response.headers.get('X-CSRF-Token');
    } else {
      console.error('Failed to fetch captcha');
    }
  } catch (error) {
    console.error('Error fetching captcha:', error);
  }
}

async function verifyCaptcha(): Promise<void> {
  const input = document.getElementById('captcha-input') as HTMLInputElement;
  const resultDiv = document.getElementById('result-message');

  if (!input || !resultDiv) {
    return;
  }

  const userInput = input.value;

  if (!userInput) {
    resultDiv.className = 'message error';
    resultDiv.textContent = 'Please enter the characters.';
    return;
  }

  if (!currentChallengeId || !currentToken || !currentCsrfToken) {
    resultDiv.className = 'message error';
    resultDiv.textContent = 'Please refresh the captcha first.';
    return;
  }

  try {
    // Get behavior data (if behaviorTracker is loaded)
    const behaviorData = (window as any).getBehaviorData ? (window as any).getBehaviorData() : null;

    const response = await fetch('/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': currentCsrfToken,
      },
      body: JSON.stringify({
        captcha: userInput,
        token: currentToken,
        challengeId: currentChallengeId,
        behaviorData,
      }),
    });

    const data = await response.json();

    if (data.success) {
      resultDiv.className = 'message success';
      resultDiv.textContent = data.message;
      // Clear tokens after successful verification
      currentChallengeId = null;
      currentToken = null;
      currentCsrfToken = null;
    } else {
      resultDiv.className = 'message error';
      resultDiv.textContent = data.message;
      // Refresh captcha on failure
      setTimeout(fetchCaptcha, 1000);
    }
  } catch (error) {
    console.error('Error verifying captcha:', error);
    if (resultDiv) {
      resultDiv.className = 'message error';
      resultDiv.textContent = 'An error occurred during verification.';
    }
  }
}

// Make functions available globally
(window as any).fetchCaptcha = fetchCaptcha;
(window as any).verifyCaptcha = verifyCaptcha;
