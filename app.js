// ThreatIntel Hub State & Data Management

// Initial realistic mock threat database
let threatDatabase = [
    {
        id: "TI-89422",
        domain: "secure-paypal-login-update.com",
        url: "http://secure-paypal-login-update.com/signin/webapps/login",
        category: "Phishing",
        reporterTrust: "High",
        status: "Verified Malicious",
        dangerScore: 96,
        dateReported: "2026-06-16",
        sslEnabled: false,
        whois: {
            registrar: "Porkbun LLC",
            regDate: "2026-06-15",
            expDate: "2027-06-15",
            org: "Privacy Protect LLC (Proxy)"
        }
    },
    {
        id: "TI-89419",
        domain: "cryptowallet-ledger-recovery.net",
        url: "https://cryptowallet-ledger-recovery.net/import-keys",
        category: "Scam/Fraud",
        reporterTrust: "Medium",
        status: "Verified Malicious",
        dangerScore: 88,
        dateReported: "2026-06-16",
        sslEnabled: true,
        whois: {
            registrar: "NameCheap, Inc.",
            regDate: "2026-06-12",
            expDate: "2027-06-12",
            org: "WhoisGuard Protected"
        }
    },
    {
        id: "TI-89415",
        domain: "microsoft-security-alert-392.xyz",
        url: "http://microsoft-security-alert-392.xyz/defender/scan-error-0x8007",
        category: "Malware Domain",
        reporterTrust: "High",
        status: "Verified Malicious",
        dangerScore: 92,
        dateReported: "2026-06-15",
        sslEnabled: false,
        whois: {
            registrar: "Hostinger, UAB",
            regDate: "2026-06-14",
            expDate: "2027-06-14",
            org: "Redacted for Privacy"
        }
    },
    {
        id: "TI-89410",
        domain: "github.com",
        url: "https://github.com/trending",
        category: "Phishing",
        reporterTrust: "High",
        status: "Verified Safe",
        dangerScore: 2,
        dateReported: "2026-06-14",
        sslEnabled: true,
        whois: {
            registrar: "MarkMonitor Inc.",
            regDate: "2007-10-09",
            expDate: "2028-10-09",
            org: "GitHub, Inc."
        }
    },
    {
        id: "TI-89408",
        domain: "banking-secure-auth-chase.info",
        url: "https://banking-secure-auth-chase.info/verify-identity",
        category: "Phishing",
        reporterTrust: "Low",
        status: "Pending",
        dangerScore: 78,
        dateReported: "2026-06-14",
        sslEnabled: true,
        whois: {
            registrar: "GoDaddy.com, LLC",
            regDate: "2026-06-13",
            expDate: "2027-06-13",
            org: "Domains By Proxy, LLC"
        }
    },
    {
        id: "TI-89403",
        domain: "adobe-flash-updater-2026.com",
        url: "http://adobe-flash-updater-2026.com/files/flash-player-installer.exe",
        category: "Malware Domain",
        reporterTrust: "Medium",
        status: "Verified Malicious",
        dangerScore: 95,
        dateReported: "2026-06-13",
        sslEnabled: false,
        whois: {
            registrar: "Domain.com, LLC",
            regDate: "2026-06-05",
            expDate: "2027-06-05",
            org: "Super Privacy Service Ltd"
        }
    },
    {
        id: "TI-89399",
        domain: "google.com",
        url: "https://google.com",
        category: "Scam/Fraud",
        reporterTrust: "High",
        status: "Verified Safe",
        dangerScore: 0,
        dateReported: "2026-06-12",
        sslEnabled: true,
        whois: {
            registrar: "MarkMonitor Inc.",
            regDate: "1997-09-15",
            expDate: "2028-09-14",
            org: "Google LLC"
        }
    },
    {
        id: "TI-89395",
        domain: "free-giftcard-giveaway.top",
        url: "http://free-giftcard-giveaway.top/survey/reward",
        category: "Scam/Fraud",
        reporterTrust: "Low",
        status: "Pending",
        dangerScore: 65,
        dateReported: "2026-06-12",
        sslEnabled: false,
        whois: {
            registrar: "Alibaba Cloud Computing",
            regDate: "2026-06-10",
            expDate: "2027-06-10",
            org: "Redacted for Privacy"
        }
    }
];

// Current filtering and active state variables
let currentFilterStatus = "all";
let currentSearchQuery = "";
let selectedThreatId = null;

// Initialize App
document.addEventListener("DOMContentLoaded", () => {
    renderLedger();
    updateStatistics();
});

// View Navigation (SPA tabs switching)
function switchTab(tabName) {
    // Hide all views
    document.querySelectorAll('.content-view').forEach(view => {
        view.style.display = 'none';
    });

    // Remove active class from all sidebar nav items
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected view
    if (tabName === 'dashboard') {
        document.getElementById('view-dashboard').style.display = 'block';
        document.getElementById('nav-dashboard').classList.add('active');
    } else if (tabName === 'api') {
        document.getElementById('view-api').style.display = 'block';
        document.getElementById('nav-api').classList.add('active');
    } else if (tabName === 'about') {
        document.getElementById('view-about').style.display = 'block';
        document.getElementById('nav-about').classList.add('active');
    }
}

// Extract Domain Name from Raw URL
function extractDomain(url) {
    let domain = url.trim();
    
    // Add protocol if it doesn't exist to parse it properly
    if (!/^https?:\/\//i.test(domain)) {
        domain = 'http://' + domain;
    }
    
    try {
        const parsedUrl = new URL(domain);
        return parsedUrl.hostname.replace('www.', '');
    } catch (e) {
        return domain; // Fallback to raw input if URL class fails
    }
}

// Generate a random mock WHOIS registrar, date, and registrant organization
function generateMockWhois(domain) {
    const registrars = ["GoDaddy.com, LLC", "NameCheap, Inc.", "Porkbun LLC", "Hostinger, UAB", "MarkMonitor Inc.", "Tucows Domains Inc."];
    const orgs = ["Privacy Protection Co.", "WhoisGuard Protected", "Domains By Proxy, LLC", "Redacted for Privacy", "Super Privacy Service Ltd", "Contact Privacy Inc."];
    
    const randomRegistrar = registrars[Math.floor(Math.random() * registrars.length)];
    const randomOrg = orgs[Math.floor(Math.random() * orgs.length)];
    
    const today = new Date();
    // Registration was between 1 to 15 days ago
    const regDaysAgo = Math.floor(Math.random() * 15) + 1;
    const regDate = new Date(today);
    regDate.setDate(today.getDate() - regDaysAgo);
    
    // Expiration is exactly 1 year after registration
    const expDate = new Date(regDate);
    expDate.setFullYear(regDate.getFullYear() + 1);

    const formatDate = (date) => {
        const y = date.getFullYear();
        const m = String(date.getMonth() + 1).padStart(2, '0');
        const d = String(date.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
    };

    return {
        registrar: randomRegistrar,
        regDate: formatDate(regDate),
        expDate: formatDate(expDate),
        org: randomOrg
    };
}

// Calculate dynamic threat classification score based on input url patterns
function calculateMockThreatScore(url, category) {
    let score = 50; // default base score
    
    const hasSSL = url.toLowerCase().startsWith('https://');
    const hasIpAddress = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(url);
    const domainLength = extractDomain(url).length;
    
    // Pattern factors
    if (!hasSSL) score += 20; // major warning if no SSL
    if (hasIpAddress) score += 15; // IP addresses instead of domains are highly suspect
    if (domainLength > 25) score += 10; // overly long domains
    
    // Subdomain count
    const dots = (url.split('//')[1] || url).split('/')[0].split('.').length;
    if (dots > 3) score += 10; // high depth subdomains
    
    // Category specifics
    if (category === "Phishing") score += 10;
    if (category === "Malware Domain") score += 12;
    if (category === "Scam/Fraud") score += 5;
    
    // Clamp score
    return Math.min(Math.max(score, 10), 99);
}

// Handle Suspicious URL Form Submission
function handleReportSubmit(event) {
    event.preventDefault();

    const urlInput = document.getElementById("url-input-field");
    const categorySelect = document.getElementById("category-select-field");

    let urlValue = urlInput.value.trim();
    if (!urlValue) return;

    // Standardize URL protocol
    if (!/^https?:\/\//i.test(urlValue)) {
        urlValue = "http://" + urlValue;
    }

    const domainName = extractDomain(urlValue);
    const category = categorySelect.value;

    // Check if domain is already in ledger
    const exists = threatDatabase.find(t => t.domain.toLowerCase() === domainName.toLowerCase());
    if (exists) {
        showToast(`Warning: ${domainName} is already on the ledger with status "${exists.status}".`, "warning");
        urlInput.value = "";
        categorySelect.value = "";
        return;
    }

    const sslEnabled = urlValue.toLowerCase().startsWith("https://");
    const dangerScore = calculateMockThreatScore(urlValue, category);
    
    const newThreatId = "TI-" + (Math.floor(Math.random() * 90000) + 10000);
    const todayStr = new Date().toISOString().split('T')[0];

    const newThreatObj = {
        id: newThreatId,
        domain: domainName,
        url: urlValue,
        category: category,
        reporterTrust: "Medium", // guest submitter default
        status: "Pending",
        dangerScore: dangerScore,
        dateReported: todayStr,
        sslEnabled: sslEnabled,
        whois: generateMockWhois(domainName)
    };

    // Add to top of ledger list
    threatDatabase.unshift(newThreatObj);
    
    // Reset form fields
    urlInput.value = "";
    categorySelect.value = "";

    // UI Updates
    renderLedger();
    updateStatistics();
    
    showToast(`Successfully reported ${domainName} as a potential ${category} threat!`, "success");
}

// Render Ledger Table with Filtering and Search
function renderLedger() {
    const tableBody = document.getElementById("ledger-table-body");
    tableBody.innerHTML = "";

    // Filter list
    const filteredThreats = threatDatabase.filter(threat => {
        // Filter by verification status
        const matchesStatus = (currentFilterStatus === "all") || (threat.status === currentFilterStatus);
        
        // Filter by domain name search
        const matchesSearch = threat.domain.toLowerCase().includes(currentSearchQuery.toLowerCase()) || 
                              threat.category.toLowerCase().includes(currentSearchQuery.toLowerCase());
                              
        return matchesStatus && matchesSearch;
    });

    if (filteredThreats.length === 0) {
        tableBody.innerHTML = `
            <tr class="empty-state-row">
                <td colspan="6">
                    <div class="empty-state-container">
                        <svg viewBox="0 0 24 24">
                            <circle cx="11" cy="11" r="8"/>
                            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                            <line x1="8" y1="11" x2="14" y2="11"/>
                        </svg>
                        <span class="empty-state-title">No threat entries match your filter rules</span>
                        <p style="font-size: 0.85rem;">Try modifying your search query or switching status filters.</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    filteredThreats.forEach(threat => {
        const tr = document.createElement("tr");
        tr.onclick = () => openModal(threat.id);
        
        // Build category class
        const categoryBadge = `<span class="badge badge-category">${threat.category}</span>`;
        
        // Build status class & dot
        let statusClass = "status-pending";
        if (threat.status === "Verified Safe") statusClass = "status-safe";
        if (threat.status === "Verified Malicious") statusClass = "status-malicious";

        const statusBadge = `
            <span class="badge ${statusClass}">
                <span class="badge-dot"></span>
                ${threat.status}
            </span>
        `;

        // Trust Level Fill Bar
        let trustClass = "medium";
        if (threat.reporterTrust === "High") trustClass = "high";
        if (threat.reporterTrust === "Low") trustClass = "low";

        const trustIndicator = `
            <div class="trust-indicator-container">
                <span class="trust-level-label ${trustClass}">${threat.reporterTrust}</span>
                <div class="trust-bar-bg">
                    <div class="trust-bar-fill ${trustClass}"></div>
                </div>
            </div>
        `;

        tr.innerHTML = `
            <td class="td-domain">${threat.domain}</td>
            <td class="td-date">${threat.dateReported}</td>
            <td>${categoryBadge}</td>
            <td>${trustIndicator}</td>
            <td>${statusBadge}</td>
            <td>
                <button class="btn-view-details">
                    Details
                    <svg viewBox="0 0 24 24">
                        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                        <polyline points="15 3 21 3 21 9" />
                        <line x1="10" y1="14" x2="21" y2="3" />
                    </svg>
                </button>
            </td>
        `;

        tableBody.appendChild(tr);
    });
}

// Update Dashboard Counter Cards
function updateStatistics() {
    const total = threatDatabase.length;
    const malicious = threatDatabase.filter(t => t.status === "Verified Malicious").length;
    const safe = threatDatabase.filter(t => t.status === "Verified Safe").length;
    const pending = threatDatabase.filter(t => t.status === "Pending").length;

    animateCounter("stat-total", total);
    animateCounter("stat-malicious", malicious);
    animateCounter("stat-safe", safe);
    animateCounter("stat-pending", pending);
}

// Basic counter increment animation for stats
function animateCounter(elementId, targetVal) {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    let currentVal = parseInt(el.innerText) || 0;
    if (currentVal === targetVal) {
        el.innerText = targetVal;
        return;
    }
    
    // Set immediate update for simplicity but can step if desired
    el.innerText = targetVal;
}

// Handle Search and Filter inputs
function handleFilterChange() {
    currentSearchQuery = document.getElementById("ledger-search-input").value;
    renderLedger();
}

// Switch Table Filters Status Mode
function setFilterStatus(status) {
    currentFilterStatus = status;

    // Toggle active styles on tabs
    document.querySelectorAll(".filter-tab").forEach(tab => {
        tab.classList.remove("active");
        tab.setAttribute("aria-selected", "false");
    });

    const activeTab = document.getElementById(
        status === "all" ? "tab-all" :
        status === "Pending" ? "tab-pending" :
        status === "Verified Safe" ? "tab-safe" : "tab-malicious"
    );

    if (activeTab) {
        activeTab.classList.add("active");
        activeTab.setAttribute("aria-selected", "true");
    }

    renderLedger();
}

// Modal open controller
function openModal(threatId) {
    const threat = threatDatabase.find(t => t.id === threatId);
    if (!threat) return;

    selectedThreatId = threatId;

    // Populate standard headers
    document.getElementById("modal-domain-name").innerText = threat.domain;
    document.getElementById("modal-threat-id").innerText = threat.id;
    document.getElementById("modal-category").innerText = threat.category;
    document.getElementById("modal-date-reported").innerText = threat.dateReported;
    document.getElementById("modal-trust-level").innerText = threat.reporterTrust;

    // Populate WHOIS
    document.getElementById("whois-registrar").innerText = threat.whois.registrar;
    document.getElementById("whois-reg-date").innerText = threat.whois.regDate;
    document.getElementById("whois-exp-date").innerText = threat.whois.expDate;
    document.getElementById("whois-org").innerText = threat.whois.org;

    // Populate SSL warning certificate
    const sslBanner = document.getElementById("modal-ssl-banner");
    const sslIcon = document.getElementById("modal-ssl-icon");
    const sslTitle = document.getElementById("modal-ssl-title");
    const sslDesc = document.getElementById("modal-ssl-desc");

    if (threat.sslEnabled) {
        sslBanner.className = "ssl-warning-banner ssl-secure";
        sslIcon.innerHTML = `
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 11 11 13 15 9"/>
        `;
        sslTitle.innerText = "Valid SSL Certificate Verified";
        sslDesc.innerText = "The connection to this site is encrypted (HTTPS). However, check warning scorecards as attacks can still hide on HTTPS.";
    } else {
        sslBanner.className = "ssl-warning-banner";
        sslIcon.innerHTML = `
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
        `;
        sslTitle.innerText = "SSL Certificate Warning: Unencrypted";
        sslDesc.innerText = "This URL lacks active SSL encryption (HTTP). Most modern phishing links use insecure, newly-registered domains.";
    }

    // Danger rating gauge render
    const dangerScoreVal = document.getElementById("modal-danger-score");
    const gaugeArc = document.getElementById("gauge-fill-arc");
    const classification = document.getElementById("modal-classification");

    dangerScoreVal.innerText = threat.dangerScore;

    // Map danger classification text
    let classificationText = "PENDING ANALYSIS";
    let classificationClass = "danger-medium";
    
    if (threat.status === "Verified Safe") {
        classificationText = "VERIFIED SAFE SITE";
        classificationClass = "danger-low";
    } else if (threat.status === "Verified Malicious") {
        classificationText = "CONFIRMED THREAT LINK";
        classificationClass = "danger-high";
    } else {
        if (threat.dangerScore >= 75) {
            classificationText = "HIGH DANGER SUSPECT";
            classificationClass = "danger-high";
        } else if (threat.dangerScore >= 35) {
            classificationText = "SUSPICIOUS THREAT INDICATOR";
            classificationClass = "danger-medium";
        } else {
            classificationText = "CLEAN RATING SUSPECT";
            classificationClass = "danger-low";
        }
    }

    classification.className = "threat-classification " + classificationClass;
    classification.innerText = classificationText;

    // Trigger SVG stroke-dashoffset transition
    // Radius is 40. Circumference = 2 * PI * r = 251.2
    const circumference = 251.2;
    const progressOffset = circumference - (threat.dangerScore / 100 * circumference);
    
    // Reset and apply transition delay
    gaugeArc.style.strokeDashoffset = circumference;
    
    // Choose dynamic color for gauge ring
    let gaugeColor = "var(--pending-accent)";
    if (threat.status === "Verified Safe" || (threat.status === "Pending" && threat.dangerScore < 35)) {
        gaugeColor = "var(--safe-accent)";
    } else if (threat.status === "Verified Malicious" || (threat.status === "Pending" && threat.dangerScore >= 75)) {
        gaugeColor = "var(--malicious-accent)";
    }
    gaugeArc.style.stroke = gaugeColor;

    setTimeout(() => {
        gaugeArc.style.strokeDashoffset = progressOffset;
    }, 50);

    // Show modal overlay
    document.getElementById("threat-detail-modal").classList.add("active");
}

// Modal close controller
function closeModal(event) {
    document.getElementById("threat-detail-modal").classList.remove("active");
    selectedThreatId = null;
}

// Moderator simulation: verify threat level status toggle
function simulateModerateStatus(newStatus) {
    if (!selectedThreatId) return;

    const threat = threatDatabase.find(t => t.id === selectedThreatId);
    if (!threat) return;

    // Change DB state
    threat.status = newStatus;

    // Recalculate and update views
    renderLedger();
    updateStatistics();
    
    // Re-trigger modal open values to reflect state changes immediately
    openModal(selectedThreatId);

    showToast(`Moderation Update: Marked domain "${threat.domain}" as ${newStatus}.`, "info");
}

// Toast Notification Manager
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;

    let iconSvg = `
        <svg viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="16" x2="12" y2="12"/>
            <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
    `;
    
    if (type === "success") {
        iconSvg = `
            <svg viewBox="0 0 24 24">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
        `;
    } else if (type === "warning") {
        iconSvg = `
            <svg viewBox="0 0 24 24">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
        `;
    }

    toast.innerHTML = `
        <div class="toast-icon">${iconSvg}</div>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    // Fade out and remove after delay
    setTimeout(() => {
        toast.style.transition = "opacity 0.4s ease, transform 0.4s ease";
        toast.style.opacity = "0";
        toast.style.transform = "translateY(-10px)";
        setTimeout(() => {
            toast.remove();
        }, 400);
    }, 3500);
}
