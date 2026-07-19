// കീ സേവ് ചെയ്യാൻ
function saveApiKey() {
    const key = document.getElementById('vtApiKey').value.trim();
    localStorage.setItem('vtApiKey', key);
    alert('API Key saved successfully!');
}

// പേജ് ലോഡ് ചെയ്യുമ്പോൾ സേവ് ചെയ്ത കീ സെറ്റിംഗ്സ് ബോക്സിൽ കാണിക്കാൻ
document.addEventListener('DOMContentLoaded', () => {
    const savedKey = localStorage.getItem('vtApiKey');
    if (savedKey) {
        document.getElementById('vtApiKey').value = savedKey;
    }
});

// Tab Switcher
function openTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    document.getElementById(tabId).classList.remove('hidden');
    
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    event.currentTarget.classList.add('active');
}

// ഏത് സ്കാൻ ആണെങ്കിലും ഈ കീ എടുക്കും
function getStoredKey() {
    const key = localStorage.getItem('vtApiKey');
    if (!key) {
        alert('Please go to Settings and enter your API Key first!');
        return null;
    }
    return key;
}

// ഉദാഹരണത്തിന് URL സ്കാൻ ഫംഗ്ഷൻ ഇങ്ങനെ മാറും:
async function scanURL() {
    const apiKey = getStoredKey();
    if (!apiKey) return;
    
    const url = document.getElementById('urlInput').value.trim();
    // ബാക്കി പഴയപോലെ VirusTotal/Urlscan API റിക്വസ്റ്റ് ചെയ്യാം...
}
