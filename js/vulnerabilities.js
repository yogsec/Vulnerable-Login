/**
 * Vulnerabilities Module - Tracks login vulnerabilities only
 */

var Vulnerabilities = (function() {
    'use strict';
    
    var vulnerabilities = [];
    
    // Login-specific vulnerability definitions
    var VULN_DEFINITIONS = [
        {
            id: 'VULN-001',
            name: 'SQL Injection',
            description: 'User input is directly concatenated into SQL queries, allowing authentication bypass.',
            severity: 'critical',
            category: 'Authentication Bypass',
            cwe: 'CWE-89',
            exploited: false
        },
        {
            id: 'VULN-002',
            name: 'Plaintext Password Storage',
            description: 'Passwords are stored in plaintext in the database.',
            severity: 'critical',
            category: 'Data Exposure',
            cwe: 'CWE-312',
            exploited: false
        },
        {
            id: 'VULN-003',
            name: 'No Rate Limiting',
            description: 'No restrictions on login attempts, allowing brute force attacks.',
            severity: 'critical',
            category: 'Authentication',
            cwe: 'CWE-307',
            exploited: false
        },
        {
            id: 'VULN-004',
            name: 'No Account Lockout',
            description: 'Accounts are not locked after multiple failed login attempts.',
            severity: 'high',
            category: 'Authentication',
            cwe: 'CWE-307',
            exploited: false
        },
        {
            id: 'VULN-005',
            name: 'Weak Passwords',
            description: 'Users are created with common, easily guessable passwords.',
            severity: 'high',
            category: 'Authentication',
            cwe: 'CWE-521',
            exploited: false
        },
        {
            id: 'VULN-006',
            name: 'Weak MD5 Hashing',
            description: 'Passwords are hashed using MD5 without salt.',
            severity: 'high',
            category: 'Cryptography',
            cwe: 'CWE-327',
            exploited: false
        },
        {
            id: 'VULN-007',
            name: 'Verbose Error Messages',
            description: 'Error messages reveal whether a username exists.',
            severity: 'medium',
            category: 'Information Disclosure',
            cwe: 'CWE-209',
            exploited: false
        },
        {
            id: 'VULN-008',
            name: 'User Enumeration',
            description: 'Attackers can determine if a username exists from error messages.',
            severity: 'medium',
            category: 'Information Disclosure',
            cwe: 'CWE-203',
            exploited: false
        },
        {
            id: 'VULN-009',
            name: 'Session Fixation',
            description: 'Session ID is not regenerated after login.',
            severity: 'high',
            category: 'Authentication',
            cwe: 'CWE-384',
            exploited: false
        },
        {
            id: 'VULN-010',
            name: 'Hardcoded Credentials',
            description: 'Hardcoded backdoor credentials exist in the application.',
            severity: 'critical',
            category: 'Authentication Bypass',
            cwe: 'CWE-798',
            exploited: false
        },
        {
            id: 'VULN-011',
            name: 'No HTTPS',
            description: 'Credentials are transmitted over HTTP.',
            severity: 'medium',
            category: 'Data Exposure',
            cwe: 'CWE-319',
            exploited: false
        },
        {
            id: 'VULN-012',
            name: 'CSRF Vulnerability',
            description: 'Anti-CSRF token is not validated.',
            severity: 'medium',
            category: 'Authentication',
            cwe: 'CWE-352',
            exploited: false
        }
    ];
    
    function initVulnerabilities() {
        vulnerabilities = VULN_DEFINITIONS.map(function(v) {
            return {
                id: v.id,
                name: v.name,
                description: v.description,
                severity: v.severity,
                category: v.category,
                cwe: v.cwe,
                exploited: false,
                detected: false,
                detected_at: null
            };
        });
        
        renderVulnerabilities();
        updateVulnerabilityCount();
    }
    
    function renderVulnerabilities() {
        var container = document.getElementById('vulnerabilityList');
        if (!container) return;
        
        var html = '';
        vulnerabilities.forEach(function(v) {
            var severityClass = v.severity;
            var statusClass = v.exploited ? 'bg-success' : 'bg-' + getSeverityColor(v.severity);
            var statusText = v.exploited ? 'Exploited' : 'Active';
            
            html += '<div class="col-md-6">';
            html += '<div class="vulnerability-item">';
            html += '<span class="vuln-tag ' + severityClass + '">' + v.severity + '</span>';
            html += ' <strong>' + v.name + '</strong>';
            html += ' <span class="badge ' + statusClass + ' float-end">' + statusText + '</span>';
            html += '<br><small class="text-muted">' + v.cwe + ' | ' + v.category + '</small>';
            html += '<br><small>' + v.description + '</small>';
            html += '</div>';
            html += '</div>';
        });
        
        container.innerHTML = html;
    }
    
    function getSeverityColor(severity) {
        var colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary'
        };
        return colors[severity] || 'secondary';
    }
    
    function updateVulnerabilityCount() {
        var active = vulnerabilities.filter(function(v) { 
            return !v.exploited; 
        });
        
        var countDisplay = document.getElementById('vulnCount');
        if (countDisplay) {
            countDisplay.textContent = 'Vulnerabilities: ' + active.length;
        }
    }
    
    function detectVulnerability(id, details) {
        var vuln = vulnerabilities.find(function(v) {
            return v.id === id;
        });
        
        if (vuln && !vuln.detected) {
            vuln.detected = true;
            vuln.detected_at = new Date().toISOString();
            log('Vulnerability', 'Detected: ' + vuln.name, 'warning');
            renderVulnerabilities();
            return true;
        }
        return false;
    }
    
    function exploitVulnerability(id, payload) {
        var vuln = vulnerabilities.find(function(v) {
            return v.id === id;
        });
        
        if (vuln && !vuln.exploited) {
            vuln.exploited = true;
            vuln.exploited_at = new Date().toISOString();
            vuln.payload = payload;
            
            log('Exploit', 'SUCCESS: ' + vuln.name + ' exploited', 'danger');
            renderVulnerabilities();
            updateVulnerabilityCount();
            return true;
        }
        return false;
    }
    
    function getVulnerabilities() {
        return vulnerabilities;
    }
    
    function getActiveVulnerabilities() {
        return vulnerabilities.filter(function(v) {
            return !v.exploited;
        });
    }
    
    function log(type, message, level) {
        var console = document.getElementById('attackConsole');
        if (!console) return;
        
        var timestamp = new Date().toLocaleTimeString();
        var entry = document.createElement('div');
        entry.className = 'log-entry';
        
        var levelClass = 'log-level-' + level;
        entry.innerHTML = 
            '<span class="log-time">[' + timestamp + ']</span>' +
            '<span class="log-label">[' + type + ']</span>' +
            '<span class="' + levelClass + '">' + message + '</span>';
        
        console.appendChild(entry);
        console.scrollTop = console.scrollHeight;
    }
    
    // Public API
    return {
        initVulnerabilities: initVulnerabilities,
        renderVulnerabilities: renderVulnerabilities,
        updateVulnerabilityCount: updateVulnerabilityCount,
        detectVulnerability: detectVulnerability,
        exploitVulnerability: exploitVulnerability,
        getVulnerabilities: getVulnerabilities,
        getActiveVulnerabilities: getActiveVulnerabilities
    };
})();

window.Vulnerabilities = Vulnerabilities;