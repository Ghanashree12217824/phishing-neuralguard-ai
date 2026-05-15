const API_URL = "http://127.0.0.1:8000/predict";

document.addEventListener("DOMContentLoaded", async () => {
    const urlDisplay = document.getElementById("current-url");
    const statusCard = document.getElementById("status-card");
    const statusText = document.getElementById("status-text");
    const statusIcon = document.querySelector(".status-icon");
    const statusSubtext = document.getElementById("status-subtext");

    // Get current active tab
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0) return;
    
    const url = tabs[0].url;
    urlDisplay.textContent = url;

    // Ignore Chrome internal pages
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
        setSafe("Internal Page");
        return;
    }

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (data.error) {
            setError(data.error);
        } else if (data.prediction === "Phishing") {
            setDanger();
        } else {
            setSafe("Secure Connection");
        }
    } catch (err) {
        setError("AI Engine Offline. Ensure FastAPI is running on port 8000.");
    }

    function setSafe(msg) {
        statusCard.className = "status-card safe";
        statusIcon.className = "fa-solid fa-shield-check status-icon";
        statusText.textContent = "Safe";
        statusSubtext.textContent = msg;
    }

    function setDanger() {
        statusCard.className = "status-card danger";
        statusIcon.className = "fa-solid fa-triangle-exclamation status-icon fa-beat";
        statusText.textContent = "Phishing Detected";
        statusSubtext.textContent = "Do not enter passwords or sensitive info here!";
    }

    function setError(msg) {
        statusCard.className = "status-card";
        statusIcon.className = "fa-solid fa-server status-icon";
        statusText.textContent = "API Error";
        statusSubtext.textContent = msg;
        statusSubtext.style.color = "#f85149";
    }
});
document.getElementById("open-dashboard").addEventListener("click", () => {
    chrome.tabs.create({
        url: "http://localhost:5500"
    });
});