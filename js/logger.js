/**
 * Logger Module - Handles all logging, error tracking, and validation
 */

var Logger = (function() {
    'use strict';
    
    // Private variables
    var errorLog = [];
    var attackLog = [];
    var maxLogEntries = 1000;
    
    // Error types
    var ERROR_TYPES = {
        VALIDATION: 'Validation Error',
        SECURITY: 'Security Error',
        SYSTEM: 'System Error',
        VULNERABILITY: 'Vulnerability Detected',
        EXPLOIT: 'Exploit Attempted',
        INFO: 'Information'
    };
    
    // Severity levels
    var SEVERITY = {
        LOW: 'low',
        MEDIUM: 'medium',
        HIGH: 'high',
        CRITICAL: 'critical'
    };
    
    /**
     * Add entry to attack console
     */
    function logAttack(type, message, level) {
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
        
        // Store in attack log
        attackLog.push({
            timestamp: timestamp,
            type: type,
            message: message,
            level: level
        });
        
        // Trim if too many entries
        if (attackLog.length > maxLogEntries) {
            attackLog.shift();
        }
    }
    
    /**
     * Add entry to error log
     */
    function logError(type, message, severity, details) {
        var errorLogDiv = document.getElementById('errorLog');
        if (!errorLogDiv) return;
        
        var timestamp = new Date().toLocaleString();
        var entry = document.createElement('div');
        entry.className = 'error-entry ' + severity;
        
        var severityLabel = severity.toUpperCase();
        entry.innerHTML = 
            '[' + timestamp + '] ' +
            '<span class="text-danger">[' + severityLabel + ']</span> ' +
            '[' + type + '] ' + message +
            (details ? ' - ' + JSON.stringify(details) : '');
        
        errorLogDiv.appendChild(entry);
        errorLogDiv.scrollTop = errorLogDiv.scrollHeight;
        
        // Store in error log
        errorLog.push({
            timestamp: timestamp,
            type: type,
            message: message,
            severity: severity,
            details: details
        });
        
        // Also log to console
        console.error('[' + severityLabel + '] [' + type + '] ' + message);
        
        // Trim if too many entries
        if (errorLog.length > maxLogEntries) {
            errorLog.shift();
        }
    }
    
    /**
     * Validate input fields
     */
    function validateInput(fieldId, value, rules) {
        var errors = [];
        var field = document.getElementById(fieldId);
        
        if (!field) {
            logError('Validation', 'Field not found: ' + fieldId, 'high');
            return { valid: false, errors: ['Field not found'] };
        }
        
        // Check required
        if (rules.required && (!value || value.trim() === '')) {
            errors.push(fieldId + ' is required');
            logError('Validation', fieldId + ' is required but was empty', 'medium');
        }
        
        // Check min length
        if (rules.minLength && value && value.length < rules.minLength) {
            errors.push(fieldId + ' must be at least ' + rules.minLength + ' characters');
            logError('Validation', fieldId + ' failed min length check', 'low');
        }
        
        // Check max length
        if (rules.maxLength && value && value.length > rules.maxLength) {
            errors.push(fieldId + ' must be less than ' + rules.maxLength + ' characters');
            logError('Validation', fieldId + ' failed max length check', 'low');
        }
        
        // Check pattern
        if (rules.pattern && value && !rules.pattern.test(value)) {
            errors.push(fieldId + ' has invalid format');
            logError('Validation', fieldId + ' failed pattern validation', 'medium');
        }
        
        // Check for SQL injection patterns
        if (rules.checkSQLInjection && value) {
            var sqlPatterns = [
                /'\s*--/,
                /'\s*OR\s+'1'\s*=\s*'1/,
                /'\s*OR\s+1\s*=\s*1\s*--/,
                /'\s*UNION\s+SELECT/i,
                /'\s*;.*--/
            ];
            
            for (var i = 0; i < sqlPatterns.length; i++) {
                if (sqlPatterns[i].test(value)) {
                    errors.push('Potential SQL injection detected in ' + fieldId);
                    logError('Security', 'SQL injection attempt detected in ' + fieldId + ': ' + value, 'critical');
                    break;
                }
            }
        }
        
        // Check for XSS patterns
        if (rules.checkXSS && value) {
            var xssPatterns = [
                /<script>/i,
                /javascript:/i,
                /on\w+\s*=/i,
                /<.*>/i
            ];
            
            for (var j = 0; j < xssPatterns.length; j++) {
                if (xssPatterns[j].test(value)) {
                    errors.push('Potential XSS detected in ' + fieldId);
                    logError('Security', 'XSS attempt detected in ' + fieldId + ': ' + value, 'critical');
                    break;
                }
            }
        }
        
        // Update field validation state
        if (errors.length > 0) {
            field.classList.add('is-invalid');
            var feedback = document.getElementById(fieldId + 'Error');
            if (feedback) {
                feedback.textContent = errors.join(', ');
            }
        } else {
            field.classList.remove('is-invalid');
            var feedbackClear = document.getElementById(fieldId + 'Error');
            if (feedbackClear) {
                feedbackClear.textContent = '';
            }
        }
        
        return {
            valid: errors.length === 0,
            errors: errors
        };
    }
    
    /**
     * Get all error logs
     */
    function getErrorLog() {
        return errorLog;
    }
    
    /**
     * Get all attack logs
     */
    function getAttackLog() {
        return attackLog;
    }
    
    /**
     * Clear attack console
     */
    function clearAttackConsole() {
        var console = document.getElementById('attackConsole');
        if (console) {
            console.innerHTML = '';
            attackLog = [];
        }
    }
    
    /**
     * Clear error log
     */
    function clearErrorLog() {
        var errorLogDiv = document.getElementById('errorLog');
        if (errorLogDiv) {
            errorLogDiv.innerHTML = '';
            errorLog = [];
        }
    }
    
    /**
     * Export logs
     */
    function exportLogs() {
        var logText = '=== VULNERABLE LOGIN LAB - COMPLETE LOG ===\n';
        logText += 'Generated: ' + new Date().toLocaleString() + '\n\n';
        
        logText += '=== ATTACK LOG ===\n';
        attackLog.forEach(function(entry) {
            logText += '[' + entry.timestamp + '] [' + entry.type + '] [' + entry.level + '] ' + entry.message + '\n';
        });
        
        logText += '\n=== ERROR LOG ===\n';
        errorLog.forEach(function(entry) {
            logText += '[' + entry.timestamp + '] [' + entry.severity + '] [' + entry.type + '] ' + entry.message + '\n';
        });
        
        var blob = new Blob([logText], { type: 'text/plain' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'security-log-' + Date.now() + '.txt';
        a.click();
        URL.revokeObjectURL(url);
        
        logAttack('System', 'Logs exported successfully', 'success');
    }
    
    // Public API
    return {
        logAttack: logAttack,
        logError: logError,
        validateInput: validateInput,
        getErrorLog: getErrorLog,
        getAttackLog: getAttackLog,
        clearAttackConsole: clearAttackConsole,
        clearErrorLog: clearErrorLog,
        exportLogs: exportLogs,
        ERROR_TYPES: ERROR_TYPES,
        SEVERITY: SEVERITY
    };
})();

// Make globally available
window.Logger = Logger;