const fs = require('fs');
const path = require('path');
const axios = require('axios');

const rateLimitMap = new Map();
const BLOCKED_IP_FILE = path.join(__dirname, 'blocked_ips.json');
const IPQS_API_KEY = 'YOUR_IPQS_API_KEY'; // 🔑 <-- Replace this with your real API Key

// Ensure blocked IP file exists
function ensureBlockedFileExists() {
    if (!fs.existsSync(BLOCKED_IP_FILE)) {
        fs.writeFileSync(BLOCKED_IP_FILE, '[]');
    }
}

// Get list of blocked IPs
function getBlockedIPs() {
    ensureBlockedFileExists();
    try {
        const data = fs.readFileSync(BLOCKED_IP_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
}

// Add IP to blocked list
function blockIP(ip) {
    const blocked = getBlockedIPs();
    if (!blocked.includes(ip)) {
        blocked.push(ip);
        fs.writeFileSync(BLOCKED_IP_FILE, JSON.stringify(blocked, null, 2));
    }
}

// 🔎 Check IP using IPQualityScore API
async function isIPMalicious(ip) {
    try {
        const response = await axios.get(`https://ipqualityscore.com/api/json/ip/${IPQS_API_KEY}/${ip}`);
        const data = response.data;
        
        // High fraud score or flagged as bot/proxy
        return data.fraud_score >= 80 || data.bot === true || data.proxy === true;
    } catch (error) {
        console.error('IPQS API Error:', error.message);
        return false;
    }
}

const wafMiddleware = async (req, res, next) => {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
    ip = ip.replace('::ffff:', '').replace('::1', '127.0.0.1');

    const blockedIPs = getBlockedIPs();
    if (blockedIPs.includes(ip)) {
        return res.status(403).send(`<h1>⚠️ IP Blocked</h1><p>Your IP (${ip}) is flagged for malicious activity.</p>`);
    }

    const ipRecord = rateLimitMap.get(ip) || { attempts: 0 };

    // 🧪 Local pattern check (SQLi / XSS)
    const maliciousPatterns = [
    /script/i,
    /<[^>]*>/i,
    /DROP TABLE/i,
    /UNION SELECT/i,
    /--/i,
    /' OR '1'='1/i,
    /; EXEC xp_cmdshell/i,
    /base64_encode\(/i,
    /eval\(/i,
    /\/etc\/passwd/i,
    /php:\/\/input/i,
    /file:\/\//i,
    /document\.cookie/i,
    /XMLHttpRequest/i,
    /<?php/i,
    /curl/i,
    /exec\(/i,
    /set[\s\S]*?user[\s\S]*?=/i,
    /union[\s\S]*?select/i
];
    const checkMalicious = (data = {}) =>
        Object.values(data).some(value =>
            typeof value === 'string' && maliciousPatterns.some(pattern => pattern.test(value))
        );

    const localMalicious = checkMalicious(req.query) || checkMalicious(req.body);
    const externalMalicious = await isIPMalicious(ip);

    if (localMalicious || externalMalicious) {
        ipRecord.attempts += 1;

        if (ipRecord.attempts >= 5 || externalMalicious) {
            blockIP(ip);
            return res.status(403).send(`<h1>🚫 Suspicious Activity</h1><p>IP (${ip}) has been blocked.</p>`);
        }

        rateLimitMap.set(ip, ipRecord);
        return res.status(403).render("alert");
    }

    rateLimitMap.set(ip, { attempts: 0 });
    next();
};

module.exports = wafMiddleware;
