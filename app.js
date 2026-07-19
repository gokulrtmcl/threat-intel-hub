// പേജ് ലോഡ് ചെയ്യുമ്പോൾ API Key ഓട്ടോ ഫിൽ ചെയ്യും
document.addEventListener('DOMContentLoaded', () => {
    const savedApiKey = localStorage.getItem('vtApiKey');
    if (savedApiKey) {
        document.getElementById('vtApiKey').value = savedApiKey;
    }
});

// ടാബുകൾ മാറ്റി മാറ്റി കാണിക്കാനുള്ള ഫങ്ക്ഷൻ
function openTab(tabId) {
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(content => content.classList.add('hidden'));
    
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => btn.classList.remove('active'));
    
    document.getElementById(tabId).classList.remove('hidden');
    event.currentTarget.classList.add('active');
}

// പൊതുവായി റിസൾട്ട് കാണിക്കാനുള്ള ഫങ്ക്ഷൻ
function displayResults(stats) {
    const tbody = document.querySelector('#resultsTable tbody');
    let statusClass = 'clean';
    let statusText = 'Clean';
    
    if (stats.malicious > 0) {
        statusClass = 'malicious';
        statusText = `Malicious (${stats.malicious} engines flagged!)`;
    } else if (stats.suspicious > 0) {
        statusClass = 'suspicious';
        statusText = `Suspicious (${stats.suspicious} engines flagged)`;
    }

    tbody.innerHTML = `
        <tr>
            <td><strong>VirusTotal</strong></td>
            <td class="${statusClass}">${statusText}</td>
            <td>Harmless: ${stats.harmless} | Undetected: ${stats.undetected}</td>
        </tr>
    `;
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('results').classList.remove('hidden');
}

// 1. URL സ്കാൻ ചെയ്യാൻ
async function scanURL() {
    const urlInput = document.getElementById('urlInput').value.trim();
    const apiKey = document.getElementById('vtApiKey').value.trim();
    if (!urlInput || !apiKey) return alert('Enter URL and API Key');
    
    localStorage.setItem('vtApiKey', apiKey);
    document.getElementById('loading').classList.remove('hidden');
    
    try {
        const base64Url = btoa(urlInput).replace(/=/g, '');
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${base64Url}`, {
            headers: { 'x-apikey': apiKey }
        });
        const data = await response.json();
        displayResults(data.data.attributes.last_analysis_stats);
    } catch (err) { alert(err.message); }
}

// 2. SHA/MD5 ഹാഷ് സ്കാൻ ചെയ്യാൻ
async function scanHash() {
    const hashInput = document.getElementById('hashInput').value.trim();
    const apiKey = document.getElementById('vtApiKey').value.trim();
    if (!hashInput || !apiKey) return alert('Enter Hash and API Key');
    
    localStorage.setItem('vtApiKey', apiKey);
    document.getElementById('loading').classList.remove('hidden');
    
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hashInput}`, {
            headers: { 'x-apikey': apiKey }
        });
        if(!response.ok) throw new Error("Hash not found or invalid key");
        const data = await response.json();
        displayResults(data.data.attributes.last_analysis_stats);
    } catch (err) { 
        alert(err.message); 
        document.getElementById('loading').classList.add('hidden');
    }
}

// 3. ഫയൽ/APK നേരിട്ട് അപ്‌ലോഡ് ചെയ്ത് നോക്കാൻ
async function scanFile() {
    const fileInput = document.getElementById('fileInput').files[0];
    const apiKey = document.getElementById('vtApiKey').value.trim();
    if (!fileInput || !apiKey) return alert('Select a file and enter API Key');

    localStorage.setItem('vtApiKey', apiKey);
    document.getElementById('loading').classList.remove('hidden');

    // ഫയൽ അപ്‌ലോഡ് ചെയ്യാൻ VirusTotal വലിയ ഫയലുകൾക്ക് വേറെ മെത്തേഡ് ആണ് ഉപയോഗിക്കുന്നത്, 
    // എങ്കിലും ചെറിയ ഫയലുകൾ/APK കൾക്കായി താഴെ കാണുന്ന രീതി ഉപയോഗിക്കാം
    const formData = new FormData();
    formData.append('file', fileInput);

    try {
        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: { 'x-apikey': apiKey },
            body: formData
        });
        const data = await response.json();
        alert("File uploaded successfully for analysis! ID: " + data.data.id + "\n(Note: Large APK files might take more time to analyze on free API limits)");
        document.getElementById('loading').classList.add('hidden');
    } catch (err) { 
        alert(err.err); 
        document.getElementById('loading').classList.add('hidden');
    }
}
