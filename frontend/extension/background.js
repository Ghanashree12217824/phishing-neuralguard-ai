const API_URL = "http://127.0.0.1:8000/predict";

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only intercept main frame navigations
    if (details.frameId !== 0) return;

    const url = details.url;

    // Ignore internal pages, local server, and manual bypasses
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("http://localhost") || url.startsWith("http://127.0.0.1") || url.includes("neuralguard_bypass=true")) {
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

        if (data.prediction === "Phishing") {
            // Block the navigation by redirecting to our custom warning page
            const blockPageUrl = chrome.runtime.getURL(`block.html?url=${encodeURIComponent(url)}`);
            chrome.tabs.update(details.tabId, { url: blockPageUrl });
        }
    } catch (err) {
        console.error("AI Engine offline or error:", err);
    }
});
