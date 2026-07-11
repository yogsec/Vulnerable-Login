/**
 * Database Module - Manages user data
 */

var Database = (function() {
    'use strict';
    
    var DB_KEY = 'vuln_db';
    var MD5_KEY = 'vuln_md5';
    var SESSION_KEY = 'vuln_session';
    var USER_KEY = 'vuln_user';
    var ATTEMPTS_KEY = 'vuln_attempts';
    
    function initDatabase() {
        if (localStorage.getItem(DB_KEY)) {
            renderDatabase();
            return;
        }
        
        var users = [
            { id: 1, username: 'admin', password: 'password123', role: 'admin', failed_attempts: 0 },
            { id: 2, username: 'user', password: 'letmein', role: 'user', failed_attempts: 0 },
            { id: 3, username: 'test', password: 'test123', role: 'user', failed_attempts: 0 },
            { id: 4, username: 'backup', password: 'backup2024', role: 'admin', failed_attempts: 0 },
            { id: 5, username: 'developer', password: 'dev123', role: 'admin', failed_attempts: 0 }
        ];
        
        localStorage.setItem(DB_KEY, JSON.stringify(users));
        
        var md5Hashes = {
            'password123': '482c811da5d5b4bc6d497ffa98491e38',
            'letmein': '2b7c0d8b7b9f8b7c6a5b4c3d2e1f0a9b',
            'test123': 'cc03e747a6afbbcbf8be7668acfebee5',
            'backup2024': '5f4dcc3b5aa765d61d8327deb882cf99',
            'dev123': 'f6e0a1e2ac419a5a9c0d7c8e9f0a1b2c'
        };
        localStorage.setItem(MD5_KEY, JSON.stringify(md5Hashes));
        
        renderDatabase();
        log('System', 'Database initialized with 5 users', 'info');
        log('System', 'WARNING: Passwords stored in plaintext!', 'danger');
    }
    
    function renderDatabase() {
        var users = getUsers();
        var container = document.getElementById('userDatabase');
        if (!container) return;
        
        var html = '<table class="table table-sm table-bordered db-table">';
        html += '<thead><tr>';
        html += '<th>ID</th><th>Username</th><th>Password</th><th>Role</th>';
        html += '<th>Failed Attempts</th>';
        html += '</tr></thead><tbody>';
        
        users.forEach(function(u) {
            html += '<tr>';
            html += '<td>' + u.id + '</td>';
            html += '<td><strong>' + u.username + '</strong></td>';
            html += '<td><span class="password-plaintext">' + u.password + '</span></td>';
            html += '<td>' + u.role + '</td>';
            html += '<td>' + (u.failed_attempts || 0) + '</td>';
            html += '</tr>';
        });
        
        html += '</tbody></table>';
        html += '<div class="p-2 bg-danger text-white small">';
        html += 'VULNERABILITY: Passwords stored in plaintext!';
        html += '</div>';
        
        container.innerHTML = html;
    }
    
    function getUsers() {
        try {
            return JSON.parse(localStorage.getItem(DB_KEY) || '[]');
        } catch (e) {
            return [];
        }
    }
    
    function getUserByUsername(username) {
        var users = getUsers();
        return users.find(function(u) {
            return u.username === username;
        });
    }
    
    function getUserByCredentials(username, password) {
        var users = getUsers();
        
        var user = users.find(function(u) {
            return u.username === username && u.password === password;
        });
        
        if (!user) {
            var md5Hashes = JSON.parse(localStorage.getItem(MD5_KEY) || '{}');
            var hashed = md5Hashes[password];
            if (hashed) {
                user = users.find(function(u) {
                    return u.username === username && u.password === hashed;
                });
                if (user) {
                    log('Weak Hashing', 'Password matched using MD5 hash', 'warning');
                    Vulnerabilities.detectVulnerability('VULN-006', { username: username });
                }
            }
        }
        
        return user;
    }
    
    function incrementFailedAttempts(userId) {
        var users = getUsers();
        var user = users.find(function(u) { return u.id === userId; });
        
        if (user) {
            user.failed_attempts = (user.failed_attempts || 0) + 1;
            localStorage.setItem(DB_KEY, JSON.stringify(users));
            
            if (user.failed_attempts > 5) {
                log('No Lockout', 
                    'Account "' + user.username + '" has ' + user.failed_attempts + 
                    ' failed attempts but is NOT locked!', 'danger');
                Vulnerabilities.detectVulnerability('VULN-004', { 
                    username: user.username, 
                    attempts: user.failed_attempts 
                });
            }
            
            renderDatabase();
            return user.failed_attempts;
        }
        return 0;
    }
    
    function createSession(user) {
        var sessionId = btoa(user.username + Date.now() + Math.random());
        localStorage.setItem(SESSION_KEY, sessionId);
        localStorage.setItem(USER_KEY, JSON.stringify(user));
        
        log('Session', 'Session created for: ' + user.username, 'info');
        Vulnerabilities.detectVulnerability('VULN-009', { username: user.username });
        
        var sessionDisplay = document.getElementById('sessionDisplay');
        if (sessionDisplay) {
            sessionDisplay.textContent = sessionId;
        }
        
        return sessionId;
    }
    
    function getCurrentSession() {
        return localStorage.getItem(SESSION_KEY);
    }
    
    function getCurrentUser() {
        try {
            return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
        } catch (e) {
            return null;
        }
    }
    
    function clearSession() {
        localStorage.removeItem(SESSION_KEY);
        localStorage.removeItem(USER_KEY);
        var sessionDisplay = document.getElementById('sessionDisplay');
        if (sessionDisplay) {
            sessionDisplay.textContent = 'Not logged in';
        }
        // Hide navbar user info and logout button
        var userInfo = document.getElementById('navbarUserInfo');
        var logoutBtn = document.getElementById('navbarLogoutBtn');
        if (userInfo) userInfo.classList.add('d-none');
        if (logoutBtn) logoutBtn.classList.add('d-none');
    }
    
    function getTotalAttempts() {
        return parseInt(localStorage.getItem(ATTEMPTS_KEY) || '0');
    }
    
    function incrementTotalAttempts() {
        var attempts = getTotalAttempts() + 1;
        localStorage.setItem(ATTEMPTS_KEY, attempts);
        
        if (attempts > 10) {
            log('Rate Limiting', 
                'Total attempts: ' + attempts + ' (no rate limiting!)', 'warning');
            Vulnerabilities.detectVulnerability('VULN-003', { attempts: attempts });
        }
        
        var display = document.getElementById('attemptsDisplay');
        if (display) {
            display.textContent = attempts;
        }
        
        return attempts;
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
    
    return {
        initDatabase: initDatabase,
        renderDatabase: renderDatabase,
        getUsers: getUsers,
        getUserByUsername: getUserByUsername,
        getUserByCredentials: getUserByCredentials,
        incrementFailedAttempts: incrementFailedAttempts,
        createSession: createSession,
        getCurrentSession: getCurrentSession,
        getCurrentUser: getCurrentUser,
        clearSession: clearSession,
        getTotalAttempts: getTotalAttempts,
        incrementTotalAttempts: incrementTotalAttempts
    };
})();

window.Database = Database;