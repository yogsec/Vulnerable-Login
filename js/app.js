/**
 * Main Application - Handles login and exploits
 */

(function() {
    'use strict';
    
    document.addEventListener('DOMContentLoaded', function() {
        
        // Initialize
        Database.initDatabase();
        Vulnerabilities.initVulnerabilities();
        
        // Update displays
        var session = Database.getCurrentSession();
        if (session) {
            document.getElementById('sessionDisplay').textContent = session;
        }
        
        var attempts = Database.getTotalAttempts();
        document.getElementById('attemptsDisplay').textContent = attempts;
        
        // Check for HTTPS
        if (window.location.protocol === 'http:' && window.location.hostname !== 'localhost') {
            log('No HTTPS', 'Credentials transmitted over HTTP!', 'danger');
            Vulnerabilities.detectVulnerability('VULN-011', {});
        }
        
        // Check if user is already logged in
        var currentUser = Database.getCurrentUser();
        if (currentUser) {
            showDashboard(currentUser);
            updateNavbar(currentUser);
        }
        
        // ============================================================
        // LOGIN FORM
        // ============================================================
        
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            var username = document.getElementById('username').value;
            var password = document.getElementById('password').value;
            var csrfToken = document.getElementById('csrfToken').value;
            
            // CSRF Vulnerability
            if (csrfToken === 'fixed_token_123') {
                log('CSRF', 'CSRF token is fixed and never validated!', 'warning');
                Vulnerabilities.detectVulnerability('VULN-012', {});
            }
            
            // Check for SQL Injection FIRST
            var sqlResult = checkSQLInjection(username, password);
            if (sqlResult.isInjection) {
                log('SQL Injection', 'Payload detected: ' + sqlResult.payload, 'danger');
                log('SQL Injection', 'Authentication bypassed!', 'success');
                Vulnerabilities.exploitVulnerability('VULN-001', sqlResult.payload);
                
                // Get admin user
                var adminUser = Database.getUserByUsername('admin');
                if (adminUser) {
                    Database.createSession(adminUser);
                    showAlert('SQL Injection Successful! Logged in as Admin', 'danger');
                    log('Login', 'SQL Injection bypass - Logged in as: admin', 'success');
                    
                    // Show dashboard
                    showDashboard(adminUser);
                    updateNavbar(adminUser);
                    
                    // Update session display
                    var sessionId = Database.getCurrentSession();
                    document.getElementById('sessionDisplay').textContent = sessionId;
                    
                    // Hide login form
                    document.getElementById('loginForm').style.display = 'none';
                    document.querySelector('.card-header h4').innerHTML = '<i class="fas fa-check-circle"></i> Logged In';
                    return;
                }
            }
            
            // Check for weak passwords
            var commonPasswords = ['password', '123456', 'admin', 'letmein', 'test', 'qwerty'];
            if (commonPasswords.indexOf(password) !== -1) {
                log('Weak Password', 'Using weak password: ' + password, 'warning');
                Vulnerabilities.detectVulnerability('VULN-005', { 
                    username: username, 
                    password: password 
                });
            }
            
            // Check for hardcoded backdoor
            if (username === 'backup' && password === 'backup2024') {
                log('Backdoor', 'Hardcoded backdoor credentials used!', 'danger');
                Vulnerabilities.exploitVulnerability('VULN-010', 'backup/backup2024');
                
                var backdoorUser = Database.getUserByUsername('backup');
                if (backdoorUser) {
                    Database.createSession(backdoorUser);
                    showAlert('Backdoor access granted!', 'danger');
                    showDashboard(backdoorUser);
                    updateNavbar(backdoorUser);
                    document.getElementById('loginForm').style.display = 'none';
                    document.querySelector('.card-header h4').innerHTML = '<i class="fas fa-check-circle"></i> Logged In';
                }
                return;
            }
            
            // Process login
            var result = processLogin(username, password);
            
            if (result.success) {
                showAlert('Login successful! Welcome ' + result.user.username, 'success');
                log('Login', 'User logged in: ' + result.user.username, 'success');
                Database.incrementTotalAttempts();
                
                // Show dashboard
                showDashboard(result.user);
                updateNavbar(result.user);
                
                // Hide login form
                document.getElementById('loginForm').style.display = 'none';
                document.querySelector('.card-header h4').innerHTML = '<i class="fas fa-check-circle"></i> Logged In';
                
                // Session info
                var sessionId = Database.getCurrentSession();
                document.getElementById('sessionDisplay').textContent = sessionId;
                
            } else {
                // Increment failed attempts
                var user = Database.getUserByUsername(username);
                if (user) {
                    Database.incrementFailedAttempts(user.id);
                }
                
                // No rate limiting
                var totalAttempts = Database.getTotalAttempts();
                if (totalAttempts > 10) {
                    log('Rate Limiting', 
                        'Attempts: ' + totalAttempts + ' (no rate limiting!)', 'warning');
                }
            }
        });
        
        // ============================================================
        // NAVBAR UPDATE FUNCTION
        // ============================================================
        
        function updateNavbar(user) {
            var userInfo = document.getElementById('navbarUserInfo');
            var usernameSpan = document.getElementById('navbarUsername');
            var roleSpan = document.getElementById('navbarRole');
            var logoutBtn = document.getElementById('navbarLogoutBtn');
            
            // Show user info
            userInfo.classList.remove('d-none');
            usernameSpan.textContent = user.username;
            
            // Set role badge with appropriate color
            roleSpan.textContent = user.role;
            if (user.role === 'admin') {
                roleSpan.className = 'badge bg-danger';
                // Add admin icon
                usernameSpan.innerHTML = '<i class="fas fa-crown text-warning"></i> ' + user.username;
            } else {
                roleSpan.className = 'badge bg-info text-dark';
                usernameSpan.innerHTML = '<i class="fas fa-user-circle"></i> ' + user.username;
            }
            
            // Show logout button
            logoutBtn.classList.remove('d-none');
            
            // Add logout handler
            logoutBtn.onclick = function() {
                Database.clearSession();
                location.reload();
            };
        }
        
        // ============================================================
        // DASHBOARD FUNCTION
        // ============================================================
        
        function showDashboard(user) {
            // Get the login card
            var cardBody = document.querySelector('.card-body');
            
            // Create dashboard HTML
            var dashboardHTML = `
                <div id="dashboard">
                    <div class="alert alert-success">
                        <h5><i class="fas fa-check-circle"></i> Welcome, ${user.username}!</h5>
                        <p class="mb-0">You are logged in as <strong>${user.role}</strong></p>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <div class="card bg-light">
                                <div class="card-body text-center">
                                    <h3><i class="fas fa-user"></i></h3>
                                    <h6>User Details</h6>
                                    <small class="text-muted">Username: ${user.username}</small><br>
                                    <small class="text-muted">Role: ${user.role}</small><br>
                                    <small class="text-muted">ID: ${user.id}</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card bg-light">
                                <div class="card-body text-center">
                                    <h3><i class="fas fa-shield-alt"></i></h3>
                                    <h6>Session Info</h6>
                                    <small class="text-muted">Session ID: ${Database.getCurrentSession().substring(0, 20)}...</small><br>
                                    <small class="text-muted">Login Time: ${new Date().toLocaleTimeString()}</small><br>
                                    <small class="text-muted">Attempts: ${Database.getTotalAttempts()}</small>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i>
                        <strong>Security Notice:</strong> This is a vulnerable application. 
                        Session fixation vulnerability exists - session ID is not regenerated.
                    </div>
                    
                    <button class="btn btn-danger w-100" id="logoutBtn">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </button>
                </div>
            `;
            
            // Replace form with dashboard
            var form = document.getElementById('loginForm');
            form.innerHTML = dashboardHTML;
            
            // Add logout handler
            document.getElementById('logoutBtn').addEventListener('click', function() {
                Database.clearSession();
                location.reload();
            });
        }
        
        // ============================================================
        // SQL INJECTION CHECK FUNCTION
        // ============================================================
        
        function checkSQLInjection(username, password) {
            var patterns = [
                { pattern: /'\s*OR\s+'1'\s*=\s*'1/, name: "OR '1'='1" },
                { pattern: /'\s*OR\s+1\s*=\s*1/, name: "OR 1=1" },
                { pattern: /'\s*--/, name: "Comment --" },
                { pattern: /'\s*;/, name: "Semicolon" },
                { pattern: /'\s*UNION\s+SELECT/i, name: "UNION SELECT" },
                { pattern: /'\s*OR\s+'1'\s*=\s*'1'\s*--/, name: "OR '1'='1' --" },
                { pattern: /"\s*OR\s+"1"\s*=\s*"1/, name: "Double quote OR" },
                { pattern: /admin'--/, name: "admin'--" },
                { pattern: /' OR '1'='1/, name: "' OR '1'='1" },
                { pattern: /' OR 1=1--/, name: "' OR 1=1--" },
                { pattern: /' OR '1'='1' --/, name: "' OR '1'='1' --" },
                { pattern: /admin' OR '1'='1/, name: "admin' OR '1'='1" }
            ];
            
            for (var i = 0; i < patterns.length; i++) {
                if (patterns[i].pattern.test(username)) {
                    log('SQL Injection', 'Username contains injection pattern: ' + patterns[i].name, 'danger');
                    return {
                        isInjection: true,
                        payload: username,
                        pattern: patterns[i].name
                    };
                }
            }
            
            for (var j = 0; j < patterns.length; j++) {
                if (patterns[j].pattern.test(password)) {
                    log('SQL Injection', 'Password contains injection pattern: ' + patterns[j].name, 'danger');
                    return {
                        isInjection: true,
                        payload: password,
                        pattern: patterns[j].name
                    };
                }
            }
            
            return { isInjection: false };
        }
        
        // ============================================================
        // EXPLOIT BUTTONS
        // ============================================================
        
        document.getElementById('exploitSQLi').addEventListener('click', function() {
            var payloads = [
                "' OR '1'='1",
                "admin' --",
                "' OR 1=1--",
                "' OR '1'='1' --"
            ];
            
            var payload = payloads[0];
            document.getElementById('username').value = payload;
            document.getElementById('password').value = "anything";
            
            log('Exploit', 'SQL Injection payload loaded: ' + payload, 'danger');
            log('Exploit', 'Query: SELECT * FROM users WHERE username = \'' + payload + '\' AND password = \'anything\'', 'info');
            log('Exploit', 'This will bypass authentication!', 'danger');
            
            showAlert('SQL Injection payload loaded! Click Login to exploit.', 'danger');
            
            setTimeout(function() {
                document.getElementById('loginBtn').click();
            }, 1000);
        });
        
        document.getElementById('exploitBrute').addEventListener('click', function() {
            var commonPasswords = ['password', '123456', 'password123', 'admin', 'letmein', 'test', 'qwerty', 'abc123'];
            var username = document.getElementById('username').value || 'admin';
            
            log('Exploit', 'Starting brute force on: ' + username, 'info');
            showAlert('Brute force attack started! Watch the console.', 'info');
            
            var found = false;
            var attempts = 0;
            
            commonPasswords.forEach(function(pass, index) {
                setTimeout(function() {
                    if (!found) {
                        attempts++;
                        document.getElementById('password').value = pass;
                        log('Brute Force', 'Trying: ' + pass + ' (' + attempts + '/' + commonPasswords.length + ')', 'info');
                        
                        var user = Database.getUserByCredentials(username, pass);
                        
                        if (user) {
                            found = true;
                            log('Brute Force', 'Password found: ' + pass, 'success');
                            Vulnerabilities.exploitVulnerability('VULN-003', 'brute_force');
                            showAlert('Password found: ' + pass, 'success');
                            document.getElementById('loginBtn').click();
                        }
                    }
                }, index * 500);
            });
            
            setTimeout(function() {
                if (!found) {
                    log('Brute Force', 'Password not found in common list', 'warning');
                }
            }, commonPasswords.length * 500 + 500);
        });
        
        document.getElementById('exploitBackdoor').addEventListener('click', function() {
            document.getElementById('username').value = 'backup';
            document.getElementById('password').value = 'backup2024';
            
            log('Exploit', 'Backdoor credentials loaded: backup/backup2024', 'danger');
            showAlert('Backdoor credentials loaded! Click Login.', 'warning');
            document.getElementById('loginBtn').click();
        });
        
        // ============================================================
        // CONSOLE CONTROLS
        // ============================================================
        
        document.getElementById('clearConsole').addEventListener('click', function() {
            document.getElementById('attackConsole').innerHTML = '';
            log('System', 'Console cleared', 'info');
        });
        
        // ============================================================
        // HELPER FUNCTIONS
        // ============================================================
        
        function processLogin(username, password) {
            var user = Database.getUserByCredentials(username, password);
            
            if (user) {
                Database.createSession(user);
                Database.incrementTotalAttempts();
                return { success: true, user: user };
            }
            
            var userExists = Database.getUserByUsername(username) !== undefined;
            
            if (userExists) {
                log('User Enumeration', 'Username "' + username + '" exists but password is wrong', 'warning');
                Vulnerabilities.detectVulnerability('VULN-008', { username: username });
                showAlert('Incorrect password for user "' + username + '"', 'warning');
                return { success: false };
            } else {
                log('User Enumeration', 'Username "' + username + '" does not exist', 'warning');
                Vulnerabilities.detectVulnerability('VULN-008', { username: username });
                showAlert('User "' + username + '" not found', 'danger');
                return { success: false };
            }
        }
        
        function showAlert(message, type) {
            var alert = document.getElementById('alertMessage');
            alert.textContent = message;
            alert.className = 'alert alert-' + type;
            alert.classList.remove('d-none');
            
            clearTimeout(window.alertTimeout);
            window.alertTimeout = setTimeout(function() {
                alert.classList.add('d-none');
            }, 5000);
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
        
        log('System', 'Vulnerable Login Lab ready!', 'success');
        log('System', 'Try: SQL Injection with: \' OR \'1\'=\'1', 'info');
        log('System', 'Or click the SQL Injection button', 'info');
    });
})();