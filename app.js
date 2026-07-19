// പേജ് ലോഡ് ചെയ്യുമ്പോൾ API Key ഓട്ടോ ഫിൽ ചെയ്യും
document.addEventListener('DOMContentLoaded', () => {
    const savedApiKey = localStorage.getItem('vtApiKey');
    if (savedApiKey) {
        document.getElementById('vtApiKey').value = savedApiKey;
    }
});

// API Key ലോക്കൽ സ്റ്റോറേജിലേക്ക് സേവ് ചെയ്യാൻ
function saveApiKey() {
    const key = document.getElementById('vtApiKey').value.trim();
    if (!key) return alert('Please enter a valid API Key');
    localStorage.setItem('vtApiKey', key);
    alert('🔑 API Key saved securely in your browser!');
}

// ടാബുകൾ മാറ്റി മാറ്റി കാണിക്കാനുള്ള ഫങ്ക്ഷൻ
function openTab(tabId) {
    // എല്ലാ ടാബ് കണ്ടെന്റുകളും ഒളിപ്പിക്കുക
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(content => content.classList.add('hidden'));
    
    // എല്ലാ ടാബ് ബട്ടണുകളിൽ നിന്നും active ക്ലാസ്സ് കളയുക
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => btn.classList.remove('active'));
    
    // ക്ലിക്ക് ചെയ്ത ടാബ് മാത്രം കാണിക്കുക
    document.getElementById(tabId).classList.remove('hidden');
    
    // ക്ലിക്ക് ചെയ്ത ബട്ടണെ ആക്ടീവ് ആക്കുക
    buttons.forEach(btn => {
        if(btn.getAttribute('onclick').includes(tabId)) {
            btn.classList.add('active');
        }
    });
}

// സേവ് ചെയ്ത കീ എടുക്കാനുള്ള ഫങ്ക്ഷൻ
function getStoredKey() {
    const key = localStorage.getItem('vtApiKey');
    if (!key) {
        alert('⚠️ Please go to the Settings tab and enter your VirusTotal API Key first!');
        openTab('settingsTab');
        return null;
    }
    return key;
}

// ടേബിളിലേക്ക് റിസൾട്ട് ചേർക്കാനുള്ള ഫങ്ക്ഷൻ
function appendRow(platform, status, details, statusClass) {
    const tbody = document.querySelector('#resultsTable tbody');
    const row = `
        <tr>
            <td><strong>${platform}</strong></td>
            <td class="${statusClass}">${status}</td>
            <td>${details}</td>
        </tr>
    `;
    tbody.innerHTML += row;
}

// 1. URL സ്കാൻ ചെയ്യാൻ
async function scanURL() {
    const apiKey = getStoredKey();
    if (!apiKey) return;

    const urlInput = document.getElementById('urlInput').value.trim();
    if (!urlInput) return alert('Please enter a URL to scan.');
    
    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = ''; // പഴയ റിസൾട്ടുകൾ ക്ലിയർ ചെയ്യുന്നു
    
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.remove('hidden');
    
    // --- VIRUSTOTAL URL SCAN ---
    try {
        const base64Url = btoa(urlInput).replace(/=/g, '');
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${base64Url}`, {
            headers: { 'x-apikey': apiKey }
        });
        
        if (!response.ok) throw new Error("VT Scan Failed");
        
        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;
        
        let vtStatus = 'Clean';
        let vtClass = 'clean';
        if (stats.malicious > 0) { vtStatus = 'Malicious'; vtClass = 'malicious'; }
        else if (stats.suspicious > 0) { vtStatus = 'Suspicious'; vtClass = 'suspicious'; }
        
        appendRow(
            'VirusTotal', 
            `${vtStatus} (${stats.malicious} Flags)`, 
            `Harmless: ${stats.harmless} | Undetected: ${stats.undetected}`, 
            vtClass
        );
    } catch (err) { 
        appendRow('VirusTotal', 'Error', 'Failed to fetch or invalid URL/Key', 'malicious'); 
    }

    // --- URLSCAN.IO SEARCH ---
    try {
        const urlscanRes = await fetch(`https://urlscan.io/api/v1/search/?q=page.url:"${encodeURIComponent(urlInput)}"`);
        if (urlscanRes.ok) {
            const urlscanData = await urlscanRes.json();
            if (urlscanData.results && urlscanData.results.length > 0) {
                const topResult = urlscanData.results[0];
                const isMalicious = topResult.verdicts?.overall?.malicious || false;
                let usStatus = isMalicious ? 'Malicious' : 'Clean';
                let usClass = isMalicious ? 'malicious' : 'clean';
                
                appendRow(
                    'Urlscan.io', 
                    usStatus, 
                    `IP: ${topResult.page.ip || 'N/A'} | Country: ${topResult.page.country || 'N/A'}`, 
                    usClass
                );
            } else {
                appendRow('Urlscan.io', 'No History', 'This URL has not been scanned before on urlscan.io', 'suspicious');
            }
        }
    } catch (err) {
        appendRow('Urlscan.io', 'Skipped', 'Could not fetch history data', 'suspicious');
    }

    document.getElementById('loading').classList.add('hidden');
}

// 2. SHA/MD5 ഹാഷ് സ്കാൻ ചെയ്യാൻ
async function scanHash() {
    const apiKey = getStoredKey();
    if (!apiKey) return;

    const hashInput = document.getElementById('hashInput').value.trim();
    if (!hashInput) return alert('Please enter a hash value.');
    
    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = '';
    
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.remove('hidden');
    
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hashInput}`, {
            headers: { 'x-apikey': apiKey }
        });
        if(!response.ok) throw new Error("Hash not found");
        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;
        
        let statusClass = stats.malicious > 0 ? 'malicious' : 'clean';
        let statusText = stats.malicious > 0 ? 'Malicious' : 'Clean';
        
        appendRow('VirusTotal (Hash)', `${statusText} (${stats.malicious} Flags)`, `Harmless: ${stats.harmless} | Undetected: ${stats.undetected}`, statusClass);
    } catch (err) { 
        appendRow('VirusTotal (Hash)', 'Not Found', 'Hash not found in database or API error', 'suspicious');
    } finally {
        document.getElementById('loading').classList.add('hidden');
    }
}

// 3. ഫയൽ/APK നേരിട്ട് അപ്‌ലോഡ് ചെയ്ത് നോക്കാൻ
async function scanFile() {
    const apiKey = getStoredKey();
    if (!apiKey) return;

    const fileInput = document.getElementById('fileInput').files[0];
    if (!fileInput) return alert('Please select a file first.');

    document.getElementById('loading').classList.remove('hidden');
    const formData = new FormData();
    formData.append('file', fileInput);

    try {
        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: { 'x-apikey': apiKey },
            body: formData
        });
        const data = await response.json();
        alert("📁 File uploaded successfully! Analysis ID: " + data.data.id + "\nYour file is queuing for scan.");
    } catch (err) { 
        alert("Error: " + err.message); 
    } finally {
        document.getElementById('loading').classList.add('hidden');
    }
}
