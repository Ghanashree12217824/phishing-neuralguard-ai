const API_BASE_URL = 'http://127.0.0.1:8000';

// DOM Elements
const form = document.getElementById('analyze-form');
const urlInput = document.getElementById('url-input');
const loadingIndicator = document.getElementById('loading');
const resultsContainer = document.getElementById('results-container');
const errorPanel = document.getElementById('error-message');
const threatStatus = document.getElementById('threat-status');
const confidenceBadge = document.getElementById('confidence-badge');
const gaugeFill = document.getElementById('gauge-fill');
const gaugeValue = document.getElementById('gauge-value');
const displayUrl = document.getElementById('display-url');
const actionRec = document.getElementById('action-rec');
const explainBtn = document.getElementById('explain-btn');
const explainLoading = document.getElementById('explain-loading');
const shapResults = document.getElementById('shap-results');
const explainEmpty = document.getElementById('explain-empty');
const riskList = document.getElementById('risk-list');
const safeList = document.getElementById('safe-list');
const historyPanel = document.getElementById('history-panel');
const historyList = document.getElementById('history-list');

// Advanced Features DOM
const sandboxImage = document.getElementById('sandbox-image');
const sandboxLoading = document.getElementById('sandbox-loading');
const intelLoading = document.getElementById('intel-loading');
const intelResults = document.getElementById('intel-results');
const intelIp = document.getElementById('intel-ip');
const intelLoc = document.getElementById('intel-loc');
const intelIsp = document.getElementById('intel-isp');
const intelAge = document.getElementById('intel-age');
const intelSsl = document.getElementById('intel-ssl');

// State
let currentUrl = '';
let history = [];

// Initialize history from localStorage if available
try {
    const saved = localStorage.getItem('phishing_history');
    if (saved) {
        history = JSON.parse(saved);
        updateHistoryUI();
    }
} catch (e) {}

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    currentUrl = url;
    
    // Reset UI
    resultsContainer.classList.add('hidden');
    errorPanel.classList.add('hidden');
    loadingIndicator.classList.remove('hidden');
    
    // Start Hacker Animation
    startMatrixAnimation();
    
    // Reset explain panel
    shapResults.classList.add('hidden');
    explainEmpty.classList.remove('hidden');

    // Reset Advanced Panels
    sandboxImage.classList.add('hidden');
    sandboxImage.src = '';
    sandboxLoading.classList.remove('hidden');
    
    intelResults.classList.add('hidden');
    intelLoading.classList.remove('hidden');
    
    // Load Snapshot safely via WordPress mshots API (Free and no auth required)
    sandboxImage.src = `https://s.wordpress.com/mshots/v1/${encodeURIComponent(url)}?w=1000`;
    sandboxImage.onload = () => {
        sandboxLoading.classList.add('hidden');
        sandboxImage.classList.remove('hidden');
    };

    try {
        // 1. Fire Predict API and handle immediately
        const predictPromise = fetch(`${API_BASE_URL}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        }).then(res => res.json()).then(data => {
            if (data.error) {
                showError(data.error);
            } else {
                showResults(data);
                addToHistory(url, data.prediction);
            }
        });
        
        // 2. Fire Intel API independently and update panel when done
        fetch(`${API_BASE_URL}/intel`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        }).then(res => res.json()).then(intelData => {
            if (!intelData.error) {
                intelLoading.classList.add('hidden');
                intelResults.classList.remove('hidden');
                
                intelIp.textContent = intelData.ip;
                intelLoc.textContent = intelData.geo.country !== 'Unknown' ? `${intelData.geo.city}, ${intelData.geo.country}` : 'Unknown';
                intelIsp.textContent = intelData.geo.isp;
                
                if (intelData.domain_age_days > 0) {
                    intelAge.textContent = `${intelData.domain_age_days} days`;
                    if (intelData.domain_age_days < 30) {
                        intelAge.innerHTML += ` <i class="fa-solid fa-triangle-exclamation text-danger" title="Very young domain!"></i>`;
                    }
                } else {
                    intelAge.textContent = 'Unknown';
                }
                
                if (intelData.ssl_valid) {
                    intelSsl.innerHTML = `<span class="text-success"><i class="fa-solid fa-lock"></i> Valid</span>`;
                } else {
                    intelSsl.innerHTML = `<span class="text-danger"><i class="fa-solid fa-lock-open"></i> Invalid / None</span>`;
                }
            }
        }).catch(err => console.error("Intel fetch failed", err));

        // 3. Await ONLY the fast ML prediction so the main UI unblocks instantly!
        await predictPromise;

    } catch (err) {
        showError('Failed to connect to the analysis engine. Is the backend running?');
        console.error(err);
    } finally {
        loadingIndicator.classList.add('hidden');
    }
});

explainBtn.addEventListener('click', async () => {
    if (!currentUrl) return;

    explainEmpty.classList.add('hidden');
    explainLoading.classList.remove('hidden');
    shapResults.classList.add('hidden');

    try {
        const response = await fetch(`${API_BASE_URL}/explain`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: currentUrl })
        });

        const data = await response.json();

        if (data.error) {
            showError(data.error);
        } else {
            showExplainResults(data);
        }
    } catch (err) {
        showError('Failed to fetch explanation data.');
        console.error(err);
    } finally {
        explainLoading.classList.add('hidden');
    }
});

function showResults(data) {
    resultsContainer.classList.remove('hidden');
    displayUrl.textContent = data.url;
    
    const isPhishing = data.prediction === 'Phishing';
    const confPct = Math.round(data.confidence * 100);
    
    // Set Status Text
    threatStatus.textContent = isPhishing ? 'Threat Detected' : 'Safe to Proceed';
    threatStatus.style.color = isPhishing ? 'var(--danger)' : 'var(--success)';
    
    // Set Badge
    confidenceBadge.textContent = `${confPct}% Confident`;
    confidenceBadge.style.color = isPhishing ? 'var(--danger)' : 'var(--success)';
    confidenceBadge.style.borderColor = isPhishing ? 'var(--danger)' : 'var(--success)';
    
    // Animate Gauge
    const gaugeColor = isPhishing ? 'var(--danger)' : 'var(--success)';
    gaugeFill.style.stroke = gaugeColor;
    
    // Stroke dashoffset calculation:
    // Full arc is 125.6
    // value = 0% -> offset = 125.6
    // value = 100% -> offset = 0
    const offset = 125.6 - (125.6 * (confPct / 100));
    
    // Slight delay to ensure CSS transition triggers
    setTimeout(() => {
        gaugeFill.style.strokeDashoffset = offset;
    }, 50);
    
    // Animate numbers
    animateValue(gaugeValue, 0, confPct, 1000);

    // Actions
    if (isPhishing) {
        actionRec.className = 'action-recommendation action-danger';
        actionRec.innerHTML = '<i class="fa-solid fa-ban"></i> <span>Block all interaction immediately. Do not click any links or enter credentials.</span>';
    } else {
        actionRec.className = 'action-recommendation action-safe';
        actionRec.innerHTML = '<i class="fa-solid fa-check-circle"></i> <span>Domain patterns appear normal. Safe to proceed with normal caution.</span>';
    }
}

function showExplainResults(data) {
    shapResults.classList.remove('hidden');
    riskList.innerHTML = '';
    safeList.innerHTML = '';
    
    const featureNames = [
        "URL Length", "Dots", "IP Address", "Special Characters",
        "Digits", "Suspicious Keywords", "HTTPS",
        "Subdomains", "Entropy", "F1", "F2", "F3"
    ];
    
    const shapVals = data.shap_values;
    
    // Combine names and values, then sort by absolute magnitude
    let impacts = featureNames.map((name, i) => ({ name, val: shapVals[i] }));
    impacts.sort((a, b) => Math.abs(b.val) - Math.abs(a.val));
    
    let risksAdded = 0;
    let safesAdded = 0;
    
    // Add top 4 to respective lists
    impacts.forEach(item => {
        if (item.val > 0 && risksAdded < 4) {
            const li = document.createElement('li');
            li.innerHTML = `<span>${item.name}</span> <span class="text-danger">+${item.val.toFixed(3)}</span>`;
            riskList.appendChild(li);
            risksAdded++;
        } else if (item.val < 0 && safesAdded < 4) {
            const li = document.createElement('li');
            li.innerHTML = `<span>${item.name}</span> <span class="text-success">${item.val.toFixed(3)}</span>`;
            safeList.appendChild(li);
            safesAdded++;
        }
    });

    if (risksAdded === 0) riskList.innerHTML = '<li><span class="text-muted">None detected</span></li>';
    if (safesAdded === 0) safeList.innerHTML = '<li><span class="text-muted">None detected</span></li>';
}

function showError(msg) {
    errorPanel.textContent = msg;
    errorPanel.classList.remove('hidden');
    setTimeout(() => {
        errorPanel.classList.add('hidden');
    }, 5000);
}

function addToHistory(url, prediction) {
    history.unshift({ url, prediction, time: new Date().toISOString() });
    if (history.length > 5) history.pop();
    
    try {
        localStorage.setItem('phishing_history', JSON.stringify(history));
    } catch(e) {}
    
    updateHistoryUI();
}

function updateHistoryUI() {
    if (history.length === 0) return;
    
    historyPanel.classList.remove('hidden');
    historyList.innerHTML = '';
    
    history.forEach(item => {
        const li = document.createElement('li');
        const isPhish = item.prediction === 'Phishing';
        const colorClass = isPhish ? 'history-phishing' : 'history-safe';
        const icon = isPhish ? '<i class="fa-solid fa-bug"></i>' : '<i class="fa-solid fa-shield-check"></i>';
        
        li.innerHTML = `
            <span class="history-url">${item.url}</span>
            <span class="${colorClass}">${icon} ${item.prediction}</span>
        `;
        historyList.appendChild(li);
    });
}

function animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        obj.innerHTML = Math.floor(progress * (end - start) + start) + '%';
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

// ==========================================
// ADVANCED INTERACTIVE EFFECTS
// ==========================================

// 1. 3D Tilt Effect for Glass Panels
const glassPanels = document.querySelectorAll('.glass-panel');
document.addEventListener('mousemove', (e) => {
    let xAxis = (window.innerWidth / 2 - e.pageX) / 100;
    let yAxis = (window.innerHeight / 2 - e.pageY) / 100;
    
    // Constrain rotation to prevent extreme zoom-in on the edges
    xAxis = Math.max(-5, Math.min(5, xAxis));
    yAxis = Math.max(-5, Math.min(5, yAxis));
    
    glassPanels.forEach(panel => {
        panel.style.transform = `perspective(1000px) rotateY(${xAxis}deg) rotateX(${yAxis}deg)`;
    });
});

// 2. Matrix Decoding Animation
function startMatrixAnimation() {
    const matrixCode = document.getElementById('matrix-code');
    const typingText = document.getElementById('typing-text');
    matrixCode.innerHTML = '';
    
    const phrases = [
        "Initializing neural network...",
        "Bypassing security protocols...",
        "Extracting URL features...",
        "Running Random Forest Classifier...",
        "Calculating SHAP values..."
    ];
    
    let phraseIdx = 0;
    typingText.textContent = phrases[0];
    
    const typeInterval = setInterval(() => {
        phraseIdx = (phraseIdx + 1) % phrases.length;
        typingText.textContent = phrases[phraseIdx];
    }, 800);
    
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';
    const matrixInterval = setInterval(() => {
        let randomStr = '';
        for(let i=0; i<50; i++) {
            randomStr += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        matrixCode.innerHTML = randomStr + '<br>' + matrixCode.innerHTML;
    }, 50);
    
    // Stop after API returns by attaching to a global closer or just relying on hidden class
    window.currentMatrixInterval = matrixInterval;
    window.currentTypeInterval = typeInterval;
}

// Stop animation helper
const originalShowResults = showResults;
showResults = function(data) {
    clearInterval(window.currentMatrixInterval);
    clearInterval(window.currentTypeInterval);
    originalShowResults(data);
};
const originalShowError = showError;
showError = function(msg) {
    clearInterval(window.currentMatrixInterval);
    clearInterval(window.currentTypeInterval);
    originalShowError(msg);
};

// 3. Interactive Particle Background
const canvas = document.getElementById('particle-canvas');
const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let particlesArray = [];
const mouse = { x: null, y: null, radius: 150 };

window.addEventListener('mousemove', function(event) {
    mouse.x = event.x;
    mouse.y = event.y;
});

class Particle {
    constructor(x, y, directionX, directionY, size, color) {
        this.x = x;
        this.y = y;
        this.directionX = directionX;
        this.directionY = directionY;
        this.size = size;
        this.color = color;
    }
    draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2, false);
        ctx.fillStyle = this.color;
        ctx.fill();
    }
    update() {
        if (this.x > canvas.width || this.x < 0) this.directionX = -this.directionX;
        if (this.y > canvas.height || this.y < 0) this.directionY = -this.directionY;
        
        let dx = mouse.x - this.x;
        let dy = mouse.y - this.y;
        let distance = Math.sqrt(dx*dx + dy*dy);
        if (distance < mouse.radius) {
            this.x -= dx/20;
            this.y -= dy/20;
        }
        
        this.x += this.directionX;
        this.y += this.directionY;
        this.draw();
    }
}

function initParticles() {
    particlesArray = [];
    let numberOfParticles = (canvas.height * canvas.width) / 15000;
    for (let i = 0; i < numberOfParticles; i++) {
        let size = (Math.random() * 2) + 1;
        let x = (Math.random() * ((innerWidth - size * 2) - (size * 2)) + size * 2);
        let y = (Math.random() * ((innerHeight - size * 2) - (size * 2)) + size * 2);
        let directionX = (Math.random() * 1) - 0.5;
        let directionY = (Math.random() * 1) - 0.5;
        let color = '#00f0ff';
        particlesArray.push(new Particle(x, y, directionX, directionY, size, color));
    }
}

function animateParticles() {
    requestAnimationFrame(animateParticles);
    ctx.clearRect(0, 0, innerWidth, innerHeight);
    for (let i = 0; i < particlesArray.length; i++) {
        particlesArray[i].update();
    }
    connectParticles();
}

function connectParticles() {
    let opacityValue = 1;
    for (let a = 0; a < particlesArray.length; a++) {
        for (let b = a; b < particlesArray.length; b++) {
            let distance = ((particlesArray[a].x - particlesArray[b].x) * (particlesArray[a].x - particlesArray[b].x)) + 
                           ((particlesArray[a].y - particlesArray[b].y) * (particlesArray[a].y - particlesArray[b].y));
            if (distance < (canvas.width/7) * (canvas.height/7)) {
                opacityValue = 1 - (distance/20000);
                ctx.strokeStyle = `rgba(0, 240, 255, ${opacityValue/3})`;
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(particlesArray[a].x, particlesArray[a].y);
                ctx.lineTo(particlesArray[b].x, particlesArray[b].y);
                ctx.stroke();
            }
        }
    }
}

window.addEventListener('resize', function() {
    canvas.width = innerWidth;
    canvas.height = innerHeight;
    initParticles();
});

initParticles();
animateParticles();
