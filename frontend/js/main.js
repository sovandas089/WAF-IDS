document.addEventListener('DOMContentLoaded', () => {
    // WebSocket Setup
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    let ws;

    const alertsFeed = document.getElementById('alerts-feed');
    let totalAlerts = 0;
    let totalBlocked = 0;

    function connectWs() {
        ws = new WebSocket(`${wsProto}//${window.location.host}/dashboard/ws/alerts`);
        
        ws.onopen = () => console.log("WebSocket Connected!");
        
        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            handleNewAlert(msg);
        };

        ws.onclose = () => {
            console.log("WebSocket disconnected. Retrying in 2 seconds...");
            setTimeout(connectWs, 2000);
        };
        
        ws.onerror = (err) => {
            console.error("WebSocket encountered error: ", err);
            ws.close();
        };
    }
    
    connectWs();

    function handleNewAlert(alert) {
        // Remove placeholder if it exists
        const placeholder = alertsFeed.querySelector('.placeholder-msg');
        if (placeholder) placeholder.remove();

        // Update stats
        totalAlerts++;
        document.getElementById('total-alerts').innerText = totalAlerts;
        
        if (alert.alert_type === 'brute_force') {
            totalBlocked++;
            document.getElementById('total-blocked').innerText = totalBlocked;
        }

        // Create alert element
        const el = document.createElement('div');
        el.className = `alert-item ${alert.alert_type}`;

        let typeLabel = alert.alert_type === 'brute_force' ? 'Block Event' : 'Payload Match';
        
        let snippetHtml = '';
        if (alert.content_snippet) {
            snippetHtml = `<div class="snippet">${escapeHtml(alert.content_snippet)}</div>`;
        }

        el.innerHTML = `
            <div class="alert-header">
                <span class="alert-ip">${alert.src_ip}</span>
                <span class="alert-type">${typeLabel}</span>
            </div>
            <div class="alert-message">${alert.message}</div>
            ${snippetHtml}
        `;

        alertsFeed.prepend(el);

        // Keep only last 50 alerts
        if (alertsFeed.children.length > 50) {
            alertsFeed.removeChild(alertsFeed.lastChild);
        }
    }

    // Handle PCAP Upload (Legacy/Offline Mode)
    const uploadBtn = document.getElementById('upload-btn');
    const pcapFile = document.getElementById('pcap-upload');
    const mainDashboard = document.getElementById('main-dashboard');
    const pcapDashboard = document.getElementById('pcap-dashboard');
    const pcapLogsTable = document.getElementById('pcap-logs-table');
    const backToMainBtn = document.getElementById('back-to-main-btn');

    backToMainBtn.addEventListener('click', () => {
        pcapDashboard.style.display = 'none';
        mainDashboard.style.display = 'block';
    });

    uploadBtn.addEventListener('click', async () => {
        if (!pcapFile.files[0]) {
            alert('Please select a PCAP file first.');
            return;
        }

        const formData = new FormData();
        formData.append('file', pcapFile.files[0]);

        uploadBtn.disabled = true;
        uploadBtn.innerText = 'Analyzing...';

        try {
            const res = await fetch('/dashboard/api/analyze_pcap', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            
            if (data.status === 'error') {
                alert(data.message);
                return;
            }

            // Switch views
            mainDashboard.style.display = 'none';
            pcapDashboard.style.display = 'block';
            pcapLogsTable.innerHTML = ''; // clear table

            data.logs.forEach(log => {
                const tr = document.createElement('tr');
                tr.style.borderBottom = '1px solid var(--border)';
                
                let sevColor = '#10b981'; // Green (Low)
                if (log.severity === 'CRITICAL') sevColor = '#ef4444'; // Red
                if (log.severity === 'HIGH') sevColor = '#f97316'; // Orange
                if (log.severity === 'MEDIUM') sevColor = '#f59e0b'; // Yellow

                tr.innerHTML = `
                    <td style="padding: 1rem; color: var(--text-muted);">${escapeHtml(log.timestamp)}</td>
                    <td style="padding: 1rem; font-family: monospace;">${escapeHtml(log.src_ip)}</td>
                    <td style="padding: 1rem;">${escapeHtml(log.method)} ${escapeHtml(log.path)}</td>
                    <td style="padding: 1rem;">${escapeHtml(log.reasons)}</td>
                    <td style="padding: 1rem;">
                        <span style="background-color: ${sevColor}20; color: ${sevColor}; padding: 0.2rem 0.6rem; border-radius: 4px; font-weight: bold; font-size: 0.8rem;">
                            ${escapeHtml(log.severity)}
                        </span>
                    </td>
                `;
                pcapLogsTable.appendChild(tr);
            });
            
        } catch (e) {
            console.error('Error uploading PCAP:', e);
            alert('Failed to analyze PCAP.');
        } finally {
            uploadBtn.disabled = false;
            uploadBtn.innerText = 'Analyze PCAP';
        }
    });

    // Helper to prevent XSS in snippet display
    function escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    // Rules Modal Logic
    const rulesLink = document.getElementById('link-rules');
    const rulesModal = document.getElementById('rules-modal');
    const closeBtn = document.querySelector('.close-btn');
    const rulesContent = document.getElementById('rules-content');

    rulesLink.addEventListener('click', async (e) => {
        e.preventDefault();
        rulesModal.style.display = 'flex';
        rulesContent.innerText = 'Loading...';
        try {
            const res = await fetch('/dashboard/api/rules');
            const data = await res.json();
            rulesContent.innerText = data.rules;
        } catch (err) {
            rulesContent.innerText = 'Failed to load rules.';
        }
    });

    closeBtn.addEventListener('click', () => {
        rulesModal.style.display = 'none';
    });

    window.addEventListener('click', (e) => {
        if (e.target === rulesModal) {
            rulesModal.style.display = 'none';
        }
    });

    // Smooth scroll for PCAP
    document.getElementById('link-pcap').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('pcap-upload-section').scrollIntoView({behavior: 'smooth'});
    });
});

