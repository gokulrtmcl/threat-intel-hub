document.getElementById('scanBtn').addEventListener('click', async () => {
    const urlInput = document.getElementById('urlInput').value.trim();
    const apiKey = document.getElementById('vtApiKey').value.trim();
    const loadingDiv = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const tbody = document.querySelector('#resultsTable tbody');

    if (!urlInput || !apiKey) {
        alert('Please enter both the URL and your VirusTotal API Key.');
        return;
    }

    // Reset previous results
    tbody.innerHTML = '';
    loadingDiv.classList.remove('hidden');
    resultsDiv.classList.add('hidden');

    try {
        // VirusTotal requires the URL to be base64 encoded (without padding) for the v3 API
        const base64Url = btoa(urlInput).replace(/=/g, '');

        const response = await fetch(https://www.virustotal.com/api/v3/urls/${base64Url}, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
                'accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error('Failed to fetch data from VirusTotal. Check your API key or URL.');
        }

        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;
        
        // Determine overall status
        let statusClass = 'clean';
        let statusText = 'Clean';
        
        if (stats.malicious > 0) {
            statusClass = 'malicious';
            statusText = Malicious (${stats.malicious} engines flagged this!);
        } else if (stats.suspicious > 0) {
            statusClass = 'suspicious';
            statusText = Suspicious (${stats.suspicious} engines flagged this);
        }

        // Inject row into our table
        const row = `
            <tr>
                <td><strong>VirusTotal</strong></td>
                <td class="${statusClass}">${statusText}</td>
                <td>Harmless: ${stats.harmless} | Undetected: ${stats.undetected}</td>
            </tr>
        `;
        tbody.innerHTML += row;
        
        // Later we can add more platforms (like URLVoid, AlienVault) here!

    } catch (error) {
        alert('Error: ' + error.message);
        const errorRow = <tr><td><strong>VirusTotal</strong></td><td class="malicious">Error</td><td>${error.message}</td></tr>;
        tbody.innerHTML += errorRow;
    } finally {
        loadingDiv.classList.add('hidden');
        resultsDiv.classList.remove('hidden');
    }
});
