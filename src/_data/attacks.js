const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

function getAttacks(dir, category) {
    let results = [];
    if (!fs.existsSync(dir)) {
        console.error("DIR NOT FOUND", dir);
        return results;
    }
    
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            results = results.concat(getAttacks(fullPath, category));
        } else if (file === 'meta.yaml') {
            const content = fs.readFileSync(fullPath, 'utf8');
            try {
                let dataArray = yaml.load(content);
                if (!Array.isArray(dataArray)) {
                    dataArray = [dataArray];
                }
                for (const data of dataArray) {
                    if (data && data.name) {
                        data.category = category;
                        // Ensure start_date exists
                        if (data.start_date) {
                            data.dateObj = new Date(data.start_date);
                            data.year = data.dateObj.getFullYear();
                            if (!isNaN(data.year)) {
                                data.formatted_date = data.dateObj.toISOString().split('T')[0];
                            } else {
                                data.year = 1970;
                                data.formatted_date = "Unknown Date";
                            }
                        } else {
                            data.dateObj = new Date(0);
                            data.year = 1970;
                            data.formatted_date = "Unknown Date";
                        }
                        
                        if (data.end_date) {
                            let endObj = new Date(data.end_date);
                            if (!isNaN(endObj.getTime())) {
                                data.formatted_end_date = endObj.toISOString().split('T')[0];
                                
                                if (data.formatted_date !== "Unknown Date") {
                                    let diffMs = endObj.getTime() - data.dateObj.getTime();
                                    if (diffMs >= 0) {
                                        let diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
                                        if (diffDays > 0) {
                                            data.duration = `${diffDays} day${diffDays !== 1 ? 's' : ''}`;
                                        } else {
                                            data.duration = "Same day";
                                        }
                                    }
                                }
                            } else {
                                data.formatted_end_date = "Unknown Date";
                            }
                        } else {
                            data.formatted_end_date = "Unknown Date";
                        }
                        
                        results.push(data);
                    }
                }
            } catch(e) {
                console.error("Error parsing", fullPath, e);
            }
        }
    }
    return results;
}

module.exports = function() {
    const oss = getAttacks(path.join(__dirname, '../../oss'), 'OSS');
    const proprietary = getAttacks(path.join(__dirname, '../../proprietary'), 'Proprietary');
    const all = oss.concat(proprietary);
    
    // Sort by date oldest first
    all.sort((a, b) => {
        let dateA = a.dateObj.getTime();
        let dateB = b.dateObj.getTime();
        if (isNaN(dateA)) dateA = 0;
        if (isNaN(dateB)) dateB = 0;
        return dateA - dateB;
    }); 

    // Generate unique slugs
    let slugs = new Set();
    for (let data of all) {
        let slug = data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
        let originalSlug = slug;
        let counter = 1;
        while(slugs.has(slug)) {
            slug = originalSlug + '-' + counter;
            counter++;
        }
        slugs.add(slug);
        data.slug = slug;
    }

    return all;
}
