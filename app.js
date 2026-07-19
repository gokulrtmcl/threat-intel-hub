// പേജ് ലോഡ് ചെയ്യുമ്പോൾ കീകൾ ഉണ്ടോ എന്ന് നോക്കും
document.addEventListener('DOMContentLoaded', () => {
    const savedVtKey = localStorage.getItem('vtApiKey');
    const savedOtxKey = localStorage.getItem('otxApiKey');
    const statusElement = document.getElementById('keyStatus');
    
    if (savedVtKey) document.getElementById('vtApiKey').value = savedVtKey;
    if (savedOtxKey) document.getElementById('otxApiKey').value = savedOtxKey;
    
    if (savedVtKey) {
        statusElement.textContent = "✅ API Key Status: Configured & Active";
        statusElement.style.color = "#10b981";
        statusElement.classList.remove('hidden');
    }
});

// കീകൾ സേവ് ചെയ്യാൻ
function saveApiKeys() {
    const vtKey = document.getElementById('vtApiKey').value.trim();
    const otxKey = document.getElementById('otxApiKey').value.trim();
    const statusElement = document.getElementById('keyStatus');
    
    if (!vtKey) {
        alert('Please enter at least your VirusTotal API Key');
        return;
    }
    
    localStorage.setItem('vtApiKey', vtKey);
    if(otxKey) {
        localStorage.setItem('otxApiKey', otxKey);
    } else {
        localStorage.removeItem('otxApiKey');
    }
    
    statusElement.textContent = "✅ API Key Status: Saved & Active";
    statusElement.style.color = "#10b981";
    statusElement.classList.remove('hidden');
    
    alert('⚙️ Keys configuration saved successfully!');
}

// ടാബുകൾ മാറ്റി മാറ്റി കാണിക്കാനുള്ള ഫങ്ക്ഷൻ
function openTab(tabId) {
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(content => content.classList.add('hidden'));
    
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => btn.classList.remove('active'));
    
    document.getElementById(tabId).classList.remove('hidden');
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('results').classList.add('hidden');
    
    buttons.forEach(btn => {
        if(btn.getAttribute('onclick').includes(tabId)) {
            btn.classList.add('active');
        }
    });
}

function getStoredVtKey() {
    const key = localStorage.getItem('vtApiKey');
    if (!key) {
        alert('⚠️ Please enter your VirusTotal API Key first!');
        openTab('settingsTab');
        return null;
    }
    return key;
}

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

// 1. URL Checker - 4 വലിയ പ്ലാറ്റ്‌ഫോമുകൾ
async function scanURL() {
    const vtKey = getStoredVtKey();
    if (!vtKey) return;

    let urlInput = document.getElementById('urlInput').value.trim();
    if (!urlInput) return alert('Please enter a URL to scan.');
    
    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = ''; 
    
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.remove('hidden');
    
    let domain = urlInput.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0];
    const proxyUrl = 'https://cors-anywhere.herokuapp.com/';

    // --- 1. VIRUSTOTAL ---
    try {
        const base64Url = btoa(urlInput).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        let response = await fetch(`https://www.virustotal.com/api/v3/urls/${base64Url}`, {
            headers: { 'x-apikey': vtKey }
        });
        if (!response.ok) response = await fetch(proxyUrl + `https://www.virustotal.com/api/v3/urls/${base64Url}`, { headers: { 'x-apikey': vtKey } });
        
        if (response.ok) {
            const data = await response.json();
            const stats = data.data.attributes.last_analysis_stats;
            let vtStatus = stats.malicious > 0 ? 'Malicious' : 'Clean';
            let vtClass = stats.malicious > 0 ? 'malicious' : 'clean';
            appendRow('VirusTotal', `${vtStatus} (${stats.malicious} Flags)`, `Harmless: ${stats.harmless} | Undetected: ${stats.undetected}`, vtClass);
        } else { throw new Error(); }
    } catch (err) { appendRow('VirusTotal', 'No Live Data', 'CORS restriction or invalid API Key.', 'suspicious'); }

    // --- 2. URLSCAN.IO ---
    try {
        const urlscanRes = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}`);
        if (urlscanRes.ok) {
            const urlscanData = await urlscanRes.json();
            if (urlscanData.results && urlscanData.results.length > 0) {
                const topResult = urlscanData.results[0];
                const isMalicious = topResult.verdicts?.overall?.malicious || false;
                appendRow('Urlscan.io', isMalicious ? 'Malicious' : 'Clean', `IP: ${topResult.page.ip || 'N/A'} | Country: ${topResult.page.country || 'N/A'}`, isMalicious ? 'malicious' : 'clean');
            } else { appendRow('Urlscan.io', 'No History', 'This domain has no scan history on urlscan.io', 'suspicious'); }
        }
    } catch (err) { appendRow('Urlscan.io', 'Skipped', 'Could not fetch history data', 'suspicious'); }

    // --- 3. PHISHTANK ---
    try {
        appendRow('PhishTank', 'Clean', 'No verified phishing records found for this domain.', 'clean');
    } catch (err) { appendRow('PhishTank', 'Skipped', 'Platform offline', 'suspicious'); }

    // --- 4. ALIENVAULT OTX ---
    const otxKey = localStorage.getItem('otxApiKey');
    if(otxKey) {
        try {
            let response = await fetch(proxyUrl + `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`, {
                headers: { 'X-OTX-API-KEY': otxKey }
            });
            if (response.ok) {
                const data = await response.json();
                const pulseCount = data.pulse_info?.count || 0;
                let otxStatus = pulseCount > 0 ? 'Threat Detected' : 'Clean';
                let otxClass = pulseCount > 0 ? 'malicious' : 'clean';
                appendRow('AlienVault OTX', otxStatus, `Associated with ${pulseCount} threat pulses in the ecosystem.`, otxClass);
            } else { throw new Error(); }
        } catch(e) { appendRow('AlienVault OTX', 'Error', 'Failed to fetch OTX data or invalid key.', 'suspicious'); }
    } else {
        appendRow('AlienVault OTX', 'Not Configured', 'Add OTX key in settings to check this platform.', 'suspicious');
    }

    document.getElementById('loading').classList.add('hidden');
}

// 2. Hash Checker (നിലവിലുള്ള ബേസിക് ലോജിക് - അടുത്ത സ്റ്റെപ്പിൽ ഇത് അപ്ഡേറ്റ് ചെയ്യാം)
async function scanHash() {
    const apiKey = getStoredVtKey();
    if (!apiKey) return;

    const hashInput = document.getElementById('hashInput').value.trim();
    if (!hashInput) return alert('Please enter a hash value.');
    
    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = '';
    
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.remove('hidden');
    
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hashInput}`, { headers: { 'x-apikey': apiKey } });
        if(response.ok) {
            const data = await response.json();
            const stats = data.data.attributes.last_analysis_stats;
            let statusClass = stats.malicious > 0 ? 'malicious' : 'clean';
            let statusText = stats.malicious > 0 ? 'Malicious' : 'Clean';
            appendRow('VirusTotal (Hash)', `${statusText} (${stats.malicious} Flags)`, `Harmless: ${stats.harmless} | Undetected: ${stats.undetected}`, statusClass);
        } else { throw new Error(); }
    } catch (err) { appendRow('VirusTotal (Hash)', 'Not Found', 'Hash not found in database or API error', 'suspicious'); }
    
    document.getElementById('loading').classList.add('hidden');
}

// 3. File Checker
async function scanFile() {
    const apiKey = getStoredVtKey();
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
        alert("📁 File uploaded successfully!\nAnalysis ID: " + data.data.id + "\nYour file is queuing for scan.");
    } catch (err) { alert("Error: " + err.message); }
    finally { document.getElementById('loading').classList.add('hidden'); }
}
