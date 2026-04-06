/**
 * main.js — Shared JavaScript for all NIDS dashboard pages
 * Handles: live clock, toast notifications, socket status, utility functions
 */

// ─────────────────────────────────────────────
// LIVE CLOCK
// ─────────────────────────────────────────────
function updateClock() {
    const el = document.getElementById('current-time');
    if (el) {
        const now = new Date();
        el.textContent = now.toLocaleTimeString('en-US', { hour12: false });
    }
}
updateClock();
setInterval(updateClock, 1000);


// ─────────────────────────────────────────────
// TOAST NOTIFICATIONS
// ─────────────────────────────────────────────

/**
 * Show a toast notification for a new alert.
 * Auto-dismisses after 5 seconds.
 *
 * @param {Object} alert - Alert object from the server
 */
function showToast(alert) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const sev = (alert.severity || 'MEDIUM').toLowerCase();
    const id  = `toast-${Date.now()}`;

    const icons = {
        critical: '🚨',
        high:     '⚠️',
        medium:   '🔔',
        low:      '📋',
    };
    const icon = icons[sev] || '🔔';

    const toast = document.createElement('div');
    toast.className = `toast sev-${sev}`;
    toast.id = id;
    toast.innerHTML = `
        <div class="toast-title">
            <span>${icon}</span>
            <span>${alert.alert_type || 'ALERT'}</span>
            <span style="margin-left:auto;font-size:0.65rem;font-family:'JetBrains Mono',monospace;color:var(--text-dim)">
                ${(alert.timestamp || '').slice(11, 19)}
            </span>
        </div>
        <div class="toast-body">
            <strong style="font-family:'JetBrains Mono',monospace;color:var(--text-mono)">
                ${alert.source_ip || ''}
            </strong>
            ${alert.description ? ' — ' + truncate(alert.description, 80) : ''}
        </div>
    `;

    container.appendChild(toast);

    // Auto-remove after 5 seconds with fade out
    setTimeout(() => {
        toast.style.transition = 'opacity 0.4s, transform 0.4s';
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 400);
    }, 5000);

    // Keep only last 4 toasts visible
    const toasts = container.querySelectorAll('.toast');
    if (toasts.length > 4) {
        toasts[0].remove();
    }
}


// ─────────────────────────────────────────────
// UTILITY FUNCTIONS
// ─────────────────────────────────────────────

/** Truncate a string to maxLen characters */
function truncate(str, maxLen) {
    if (!str) return '';
    return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
}

/** Format a number with thousands separators */
function formatNumber(n) {
    return (n || 0).toLocaleString();
}

/** Format a timestamp to "HH:MM:SS" */
function formatTime(ts) {
    if (!ts) return '--:--:--';
    return String(ts).slice(11, 19) || ts;
}

/** Severity color map */
const SEV_COLORS = {
    CRITICAL: '#ff2d55',
    HIGH:     '#ff7f00',
    MEDIUM:   '#ffd700',
    LOW:      '#2ed573',
};

function getSeverityColor(severity) {
    return SEV_COLORS[(severity || '').toUpperCase()] || '#8892a4';
}


// ─────────────────────────────────────────────
// SNIFFER STATUS POLLING (fallback if SocketIO unavailable)
// ─────────────────────────────────────────────
async function checkSnifferStatus() {
    try {
        const data = await fetch('/api/sniffer/status').then(r => r.json());
        const dot  = document.getElementById('sniffer-status-dot');
        const text = document.getElementById('sniffer-status-text');
        const pktEl = document.getElementById('packet-count');

        if (dot && text) {
            if (data.is_running) {
                dot.classList.add('online');
                text.textContent = 'System Online';
            } else {
                dot.classList.remove('online');
                text.textContent = 'Sniffer Stopped';
            }
        }
        if (pktEl) {
            pktEl.textContent = formatNumber(data.packet_count);
        }

        // ML Status updating
        const mlDot = document.getElementById('ml-status-dot');
        const mlText = document.getElementById('ml-status-text');
        
        if (mlDot && mlText && data.ml_info) {
            if (data.ml_info.status === "OFFLINE") {
                mlDot.style.background = "#ff2d55";
                mlDot.classList.remove('online');
                mlText.innerHTML = "🧠 AI: Missing Library";
            } else if (data.ml_info.status === "TRAINING") {
                mlDot.style.background = "#ffd700";
                mlDot.classList.add('online');
                mlText.innerHTML = `🧠 AI Training: ${data.ml_info.time_left}s...`;
                
                // Track training state to show toast notification when done
                window._ml_was_training = true;
            } else if (data.ml_info.status === "ACTIVE") {
                mlDot.style.background = "#2ed573";
                mlDot.classList.add('online');
                mlText.innerHTML = "🧠 AI: Active Detection";
                
                // Fire notification toast only once
                if (window._ml_was_training) {
                    window._ml_was_training = false;
                    showToast({
                        severity: "LOW",
                        alert_type: "AI_READY",
                        timestamp: new Date().toISOString(),
                        source_ip: "SYSTEM",
                        description: "AI Engine finished training and is now guarding your network!"
                    });
                }
            }
        }
    } catch (e) {
        // Silently fail — server might be loading
    }
}

// Poll status frequently so the timer ticks down nicely
checkSnifferStatus();
setInterval(checkSnifferStatus, 1000);


// ─────────────────────────────────────────────
// RESET DATA API
// ─────────────────────────────────────────────
function resetData() {
    if (confirm("Are you sure you want to wipe all dashboard data? This cannot be undone.")) {
        fetch("/api/reset", { method: "POST" })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success") {
                    window.location.href = "/";
                }
            })
            .catch(err => console.error(err));
    }
}


// ─────────────────────────────────────────────
// IP GEOLOCATION TRACKING (Frontend)
// ─────────────────────────────────────────────
const geoCache = {}; // Cache to avoid duplicate API calls

function isPrivateIP(ip) {
    if (!ip || ip === "—" || ip === "N/A" || ip === "None") return true;
    const parts = ip.split('.');
    if (parts.length !== 4) return true; // IPv6 or invalid
    if (parts[0] === '10' || parts[0] === '127') return true;
    if (parts[0] === '192' && parts[1] === '168') return true;
    if (parts[0] === '172' && (parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31)) return true;
    return false;
}

function countryToEmoji(countryCode) {
    if (!countryCode) return "";
    return countryCode
        .toUpperCase()
        .replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397));
}

async function enhanceIPs() {
    const ipCells = document.querySelectorAll('.ip-cell, td:nth-child(3), td:nth-child(4), .toast-body strong');
    for (let i = 0; i < ipCells.length; i++) {
        const cell = ipCells[i];
        
        // Skip if already processed
        if (cell.dataset.processed === "true") continue;
        cell.dataset.processed = "true";
        
        // Extract IP (might contain other text in some contexts)
        let rawText = cell.textContent || cell.innerText;
        let ipMatch = rawText.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
        if (!ipMatch) continue;
        let ip = ipMatch[0];

        if (isPrivateIP(ip)) continue; // ignore local networks

        let emoji = "";
        let country = "";

        if (geoCache[ip]) {
            emoji = geoCache[ip].emoji;
            country = geoCache[ip].country;
        } else {
            try {
                // Free API with no auth required
                const response = await fetch(`http://ip-api.com/json/${ip}`);
                const data = await response.json();
                
                if (data.status === "success" && data.countryCode) {
                    emoji = countryToEmoji(data.countryCode);
                    country = data.country;
                    geoCache[ip] = { emoji: emoji, country: country };
                } else {
                    geoCache[ip] = { emoji: "🌐", country: "Unknown" }; // Fallback
                    emoji = "🌐";
                    country = "Unknown";
                }
            } catch (e) {
                console.error("GeoIP error:", e);
                continue;
            }
        }

        // Append to the HTML safely
        if (emoji) {
            const span = document.createElement("span");
            span.title = country;
            span.textContent = ` ${emoji}`;
            span.style.marginLeft = "4px";
            span.style.cursor = "help";
            
            // Only append once
            if (!cell.querySelector('span[title]')) {
                 cell.appendChild(span);
            }
        }
    }
}

// Run geolocation fetcher on load and periodically in case of dynamic socket updates
enhanceIPs();
setInterval(enhanceIPs, 3000);
