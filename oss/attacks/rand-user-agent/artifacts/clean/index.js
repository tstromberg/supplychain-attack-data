const helpers = require('./helpers');
const fs = require('fs');
const path = require("path");

let content = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/user-agents.json'), 'utf8'));
content = helpers.JSONfrequencyNormalize(content);
if (helpers.JSONIsFrequency(content)) {
    content = helpers.JSONinterval(content);
}

module.exports = function(device, browser = null, os = null) {
    let options = []
    const keys = Object.keys(content)
    for (index in keys) {
        let filter = true
        if (keys[index].indexOf(device) == -1) {
            filter = false
        }
        if (browser && keys[index].indexOf(browser) == -1) {
            filter = false
        }
        if (os && keys[index].indexOf(os) == -1) {
            filter = false
        }
        if (filter) {
            options.push(keys[index])
        }
    }
    if (options.length == 0) {
        return helpers.randomElement(content[keys[Math.floor(Math.random() * keys.length)]])
    }
    return helpers.randomElement(content[options[Math.floor(Math.random() * options.length)]])
};