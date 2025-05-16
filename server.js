const express = require('express');
const os = require('os');
const fs = require('fs');
const wafMiddleware = require('./wafMiddleware');
const userAgent = require('useragent');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(wafMiddleware);
app.set('view engine', 'ejs');

// Create log file if it doesn't exist
if (!fs.existsSync('attack-logs.log')) {
  fs.writeFileSync('attack-logs.log', '========== Attack Logs ==========\n');
}

app.get('/', (req, res) => {
  const agent = userAgent.parse(req.headers['user-agent']);
  const isMobile = agent.device.family !== 'Other';
  const timestamp = new Date().toLocaleString();
  
  const logEntry = {
    timestamp,
    ip: req.ip,
    deviceType: isMobile ? 'Mobile' : 'Desktop',
    device: isMobile ? agent.device.family : 'Desktop',
    os: agent.os.family,
    browser: agent.toAgent(),
    userAgent: req.headers['user-agent'],
    additionalInfo: {}
  };

  // Add platform-specific information
  if (isMobile) {
    logEntry.additionalInfo.mobileDevice = agent.device.family;
  } else {
    logEntry.additionalInfo.desktopPlatform = agent.os.family;
  }

  // Format log entry
  const logData = `\n====== ${isMobile ? 'Mobile' : 'Desktop'} Attack @ ${timestamp} ======
Timestamp    : ${timestamp}
IP Address   : ${logEntry.ip}
Device Type  : ${logEntry.deviceType}
OS           : ${logEntry.os}
Browser      : ${logEntry.browser}
User Agent   : ${logEntry.userAgent}
${isMobile ? `Mobile Device : ${logEntry.additionalInfo.mobileDevice}` : `Desktop Platform: ${logEntry.additionalInfo.desktopPlatform}`}
=====================================`;

  // Append to log file
  fs.appendFileSync('attack-logs.log', logData);

  res.render("login");
});

app.post('/login', (req, res) => {
  res.render("userSee", { title: "User Dashboard" , username: req.body.username});
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});