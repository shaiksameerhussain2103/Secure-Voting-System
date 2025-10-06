/**
 * RSA Demo Interactive Functionality
 * Handles encryption/decryption demo and animations
 */

// Global variables
let currentEncryptedData = null;
let isAnimating = false;

// DOM elements
const demoMessage = document.getElementById('demoMessage');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const runSimulationBtn = document.getElementById('runSimulationBtn');
const originalText = document.getElementById('originalText');
const encryptedText = document.getElementById('encryptedText');
const decryptedText = document.getElementById('decryptedText');
const progressIndicator = document.getElementById('progressIndicator');
const progressFill = document.querySelector('.progress-fill');
const progressText = document.querySelector('.progress-text');
const successToast = document.getElementById('successToast');

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('RSA Demo page loaded');
    initializeDemo();
});

function initializeDemo() {
    // Set up event listeners
    encryptBtn.addEventListener('click', handleEncryption);
    decryptBtn.addEventListener('click', handleDecryption);
    runSimulationBtn.addEventListener('click', runDemoSimulation);
    
    // Update original text when input changes
    demoMessage.addEventListener('input', function() {
        originalText.textContent = this.value || 'Ready for encryption...';
        resetDemo();
    });
    
    // Initialize display
    originalText.textContent = demoMessage.value;
}

async function handleEncryption() {
    if (isAnimating) return;
    
    const message = demoMessage.value.trim();
    if (!message) {
        showError('Please enter a message to encrypt');
        return;
    }
    
    try {
        showProgress('Encrypting with RSA public key...', 30);
        highlightFlowStep('step2');
        
        const response = await fetch('/rsa_encrypt_demo', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ message: message })
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentEncryptedData = result.encrypted_message;
            
            // Update displays
            originalText.textContent = result.original_message;
            encryptedText.textContent = result.encrypted_message;
            
            // Enable decrypt button
            decryptBtn.disabled = false;
            
            // Add encryption animation
            encryptedText.parentElement.classList.add('animate-encrypt');
            
            showProgress('Encryption completed successfully!', 100);
            setTimeout(() => {
                hideProgress();
                showToast('Message encrypted successfully with ' + result.encryption_method);
            }, 1000);
            
        } else {
            throw new Error(result.error);
        }
        
    } catch (error) {
        console.error('Encryption error:', error);
        showError('Encryption failed: ' + error.message);
        hideProgress();
    }
    
    clearFlowHighlight();
}

async function handleDecryption() {
    if (isAnimating || !currentEncryptedData) return;
    
    try {
        showProgress('Decrypting with RSA private key...', 30);
        highlightFlowStep('step4');
        
        const response = await fetch('/rsa_decrypt_demo', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ encrypted_message: currentEncryptedData })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Update display
            decryptedText.textContent = result.decrypted_message;
            
            // Add decryption animation
            decryptedText.parentElement.classList.add('animate-decrypt');
            
            showProgress('Decryption completed successfully!', 100);
            setTimeout(() => {
                hideProgress();
                showToast('Message decrypted successfully with ' + result.decryption_method);
                
                // Check if original matches decrypted
                if (originalText.textContent === decryptedText.textContent) {
                    setTimeout(() => {
                        showSuccessToast();
                    }, 500);
                }
            }, 1000);
            
        } else {
            throw new Error(result.error);
        }
        
    } catch (error) {
        console.error('Decryption error:', error);
        showError('Decryption failed: ' + error.message);
        hideProgress();
    }
    
    clearFlowHighlight();
}

async function runDemoSimulation() {
    if (isAnimating) return;
    
    isAnimating = true;
    runSimulationBtn.disabled = true;
    encryptBtn.disabled = true;
    decryptBtn.disabled = true;
    
    try {
        // Step 1: Highlight input
        showProgress('Preparing vote for encryption...', 10);
        highlightFlowStep('step1');
        await sleep(1500);
        
        // Step 2: Encrypt
        showProgress('Encrypting with RSA public key...', 30);
        highlightFlowStep('step2');
        await handleEncryptionInternal();
        await sleep(2000);
        
        // Step 3: Show stored data
        showProgress('Storing encrypted vote securely...', 60);
        highlightFlowStep('step3');
        await sleep(1500);
        
        // Step 4: Decrypt
        showProgress('Admin decrypting for counting...', 80);
        highlightFlowStep('step4');
        await handleDecryptionInternal();
        await sleep(1500);
        
        // Complete
        showProgress('Demo simulation completed!', 100);
        await sleep(1000);
        
        hideProgress();
        showSuccessToast();
        
    } catch (error) {
        console.error('Simulation error:', error);
        showError('Simulation failed: ' + error.message);
        hideProgress();
    } finally {
        isAnimating = false;
        runSimulationBtn.disabled = false;
        encryptBtn.disabled = false;
        decryptBtn.disabled = false;
        clearFlowHighlight();
    }
}

async function handleEncryptionInternal() {
    const message = demoMessage.value.trim() || 'Vote for Candidate A';
    
    const response = await fetch('/rsa_encrypt_demo', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: message })
    });
    
    const result = await response.json();
    
    if (result.success) {
        currentEncryptedData = result.encrypted_message;
        originalText.textContent = result.original_message;
        encryptedText.textContent = result.encrypted_message;
        decryptBtn.disabled = false;
        
        // Add animation
        encryptedText.parentElement.classList.add('animate-encrypt');
    } else {
        throw new Error(result.error);
    }
}

async function handleDecryptionInternal() {
    if (!currentEncryptedData) return;
    
    const response = await fetch('/rsa_decrypt_demo', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ encrypted_message: currentEncryptedData })
    });
    
    const result = await response.json();
    
    if (result.success) {
        decryptedText.textContent = result.decrypted_message;
        
        // Add animation
        decryptedText.parentElement.classList.add('animate-decrypt');
    } else {
        throw new Error(result.error);
    }
}

function showProgress(text, percentage) {
    progressIndicator.style.display = 'block';
    progressText.textContent = text;
    progressFill.style.width = percentage + '%';
}

function hideProgress() {
    progressIndicator.style.display = 'none';
    progressFill.style.width = '0%';
}

function highlightFlowStep(stepId) {
    clearFlowHighlight();
    const step = document.getElementById(stepId);
    if (step) {
        step.classList.add('highlighted');
    }
}

function clearFlowHighlight() {
    document.querySelectorAll('.flow-step').forEach(step => {
        step.classList.remove('highlighted');
    });
}

function resetDemo() {
    currentEncryptedData = null;
    decryptBtn.disabled = true;
    encryptedText.textContent = 'Encryption result will appear here...';
    decryptedText.textContent = 'Decryption result will appear here...';
    
    // Remove animations
    document.querySelectorAll('.output-box').forEach(box => {
        box.classList.remove('animate-encrypt', 'animate-decrypt');
    });
}

function showError(message) {
    // Create a simple error toast
    const errorToast = document.createElement('div');
    errorToast.className = 'toast error-toast';
    errorToast.innerHTML = `
        <div class="toast-content">
            <i class="fas fa-exclamation-triangle"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(errorToast);
    errorToast.style.display = 'block';
    
    setTimeout(() => {
        errorToast.remove();
    }, 4000);
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'toast info-toast';
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas fa-info-circle"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(toast);
    toast.style.display = 'block';
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

function showSuccessToast() {
    successToast.style.display = 'block';
    setTimeout(() => {
        successToast.style.display = 'none';
    }, 4000);
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Add some visual enhancements
document.addEventListener('DOMContentLoaded', function() {
    // Add hover effects to flow steps
    document.querySelectorAll('.flow-step').forEach(step => {
        step.addEventListener('mouseenter', function() {
            if (!this.classList.contains('highlighted')) {
                this.style.transform = 'scale(1.05)';
            }
        });
        
        step.addEventListener('mouseleave', function() {
            if (!this.classList.contains('highlighted')) {
                this.style.transform = 'scale(1)';
            }
        });
    });
});