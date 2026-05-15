document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const blockedUrl = urlParams.get('url');

    const urlDisplay = document.getElementById('blocked-url');
    if (blockedUrl) {
        urlDisplay.textContent = blockedUrl;
    } else {
        urlDisplay.textContent = "Unknown URL";
    }

    // Go back to safety
    document.getElementById('btn-back').addEventListener('click', () => {
        window.history.back();
        // Fallback if no history
        setTimeout(() => {
            window.close();
        }, 500);
    });

    // Proceed anyway (bypass block)
    document.getElementById('btn-continue').addEventListener('click', () => {
        if (blockedUrl) {
            // To actually bypass, we would need to whitelist the URL in the background script.
            // For now, we will just alert the danger. A full implementation would message the background worker to whitelist this URL for 5 minutes.
            alert("Warning: Proceeding is extremely dangerous. Are you absolutely sure?");
            // We just navigate to it. Since the background script doesn't have a whitelist yet, it might just block it again in an infinite loop unless we do something complex.
            // A simple bypass for the demo is to temporarily disable the extension or implement a memory whitelist in background.js.
            // Let's implement a simple redirect with a bypass hash so background.js ignores it.
            window.location.href = blockedUrl + (blockedUrl.includes('?') ? '&' : '?') + 'neuralguard_bypass=true';
        }
    });
});
