const fs = require('fs');
const path = require('path');

function getLatestMtime(dir) {
    let latest = 0;
    if (!fs.existsSync(dir)) return latest;
    
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            const childLatest = getLatestMtime(fullPath);
            if (childLatest > latest) latest = childLatest;
        } else if (file === 'meta.yaml') {
            if (stat.mtimeMs > latest) {
                latest = stat.mtimeMs;
            }
        }
    }
    return latest;
}

module.exports = function() {
    const ossLatest = getLatestMtime(path.join(__dirname, '../../oss'));
    const propLatest = getLatestMtime(path.join(__dirname, '../../proprietary'));
    const maxLatest = Math.max(ossLatest, propLatest);
    
    if (maxLatest === 0) {
        return { lastUpdated: "Unknown" };
    }
    
    const date = new Date(maxLatest);
    // Format nicely
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return {
        lastUpdated: date.toLocaleDateString('en-US', options)
    };
};
