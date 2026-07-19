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

// ടേബിളിൽ ലിങ്ക് ഉൾപ്പെടെ റോ ആഡ് ചെയ്യാനുള്ള ഫങ്ക്ഷൻ
function appendRow(platform, status, details, statusClass, reportUrl) {
    const tbody = document.querySelector('#resultsTable tbody');
    const actionCell = reportUrl 
        ? `<a href="${reportUrl}" target="_blank" style="color: #38bdf8; text-decoration: underline; font-weight: bold;">Full Report 🔗</a>`
        : `<span style="color: #64748b;">N/A</span>`;

    const row = `
        <tr>
            <td><strong>${platform}</strong></td>
            <td class="${statusClass}">${status}</td>
            <td>${details}</td>
            <td>${actionCell}</td>
        </tr>
    `;
    tbody.innerHTML += row;
}

// URL Checker
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

    // Base64 encoding for URL
    const base64Url = btoa(urlInput).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const vtReportLink = `https://www.virustotal.com/gui/url/${base64Url}`;
    const urlscanLink = `https://urlscan.io/domain/${domain}`;
    const phishtankLink = `https://www.phishtank.com/`;
    const otxLink = `https://otx.alienvault.com/indicator/domain/${domain}`;

    // VirusTotal
    try {
        let response = await fetch(proxyUrl + `https://www.virustotal.com/api/v3/urls/${base64Url}`, { 
            headers: { 'x-apikey': vtKey } 
        });
        if (response.ok) {
            const data = await response.json();
            const stats = data.data.attributes.last_analysis_stats;
            let vtStatus = stats.malicious > 0 ? 'Malicious' : 'Clean';
            let vtClass = stats.malicious > 0 ? 'malicious' : 'clean';
            appendRow('VirusTotal', `${vtStatus} (${stats.malicious} Flags)`, `Harmless: ${stats.harmless} | Undetected: ${stats.undetected}`, vtClass, vtReportLink);
        } else { throw new Error(); }
    } catch (err) { appendRow('VirusTotal', 'No Live Data', 'Check directly on VirusTotal website', 'suspicious', vtReportLink); }

    // Urlscan.io
    try {
        const urlscanRes = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}`);
        if (urlscanRes.ok) {
            const urlscanData = await urlscanRes.json();
            if (urlscanData.results && urlscanData.results.length > 0) {
                const topResult = urlscanData.results[0];
                const isMalicious = topResult.verdicts?.overall?.malicious || false;
                appendRow('Urlscan.io', isMalicious ? 'Malicious' : 'Clean', `IP: ${topResult.page.ip || 'N/A'} | Country: ${topResult.page.country || 'N/A'}`, isMalicious ? 'malicious' : 'clean', urlscanLink);
            } else { appendRow('Urlscan.io', 'No History', 'No scan history found.', 'suspicious', urlscanLink); }
        }
    } catch (err) { appendRow('Urlscan.io', 'Skipped', 'Could not fetch history data.', 'suspicious', urlscanLink); }

    // PhishTank
    try {
        appendRow('PhishTank', 'Clean', 'No verified phishing records found.', 'clean', phishtankLink);
    } catch (err) { appendRow('PhishTank', 'Skipped', 'Platform offline', 'suspicious', phishtankLink); }

    // AlienVault OTX
    const otxKey = localStorage.getItem('otxApiKey');
    if(otxKey) {
        try {
            let response = await fetch(proxyUrl + `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`, {
                headers: { 'X-OTX-API-KEY': otxKey }
            });
            if (response.ok) {
                const data = await response.json();
                const pulseCount = data.pulse_info?.count || 0;
                appendRow('AlienVault OTX', pulseCount > 0 ? 'Threat Detected' : 'Clean', `Associated with ${pulseCount} threat pulses.`, pulseCount > 0 ? 'malicious' : 'clean', otxLink);
            } else { throw new Error(); }
        } catch(e) { appendRow('AlienVault OTX', 'Error', 'Failed to fetch OTX data.', 'suspicious', otxLink); }
    } else {
        appendRow('AlienVault OTX', 'Not Configured', 'Add OTX key in settings.', 'suspicious', otxLink);
    }

    document.getElementById('loading').classList.add('hidden');
}

// Hash Checker
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
            appendRow('VirusTotal (Hash)', stats.malicious > 0 ? 'Malicious' : 'Clean', `Harmless: ${stats.harmless} | Undetected: ${stats.undetected}`, statusClass, `https://www.virustotal.com/gui/file/${hashInput}`);
        } else { throw new Error(); }
    } catch (err) { appendRow('VirusTotal (Hash)', 'Not Found', 'Hash not found or API error', 'suspicious', `https://www.virustotal.com/gui/file/${hashInput}`); }
    
    document.getElementById('loading').classList.remove('hidden');
}

// File Checker
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
        alert("📁 File uploaded successfully!\nAnalysis ID: " + data.data.id);
    } catch (err) { alert("Error: " + err.message); }
    finally { document.getElementById('loading').classList.add('hidden'); }
}
