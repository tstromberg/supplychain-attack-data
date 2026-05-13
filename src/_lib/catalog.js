const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

function slugify(value) {
    return String(value || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)+/g, '');
}

function uniqueSlugs(records) {
    const slugs = new Set();
    for (const record of records) {
        const base = slugify(record.id);
        let slug = base;
        let counter = 1;
        while (slugs.has(slug)) {
            slug = `${base}-${counter}`;
            counter++;
        }
        slugs.add(slug);
        record.slug = slug;
    }
}

function loadYamlRecords(dir, options = {}) {
    let results = [];
    if (!fs.existsSync(dir)) {
        return results;
    }

    const files = fs.readdirSync(dir);
    for (const file of files) {
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            results = results.concat(loadYamlRecords(fullPath, options));
            continue;
        }
        if (file !== 'meta.yaml') {
            continue;
        }

        const content = fs.readFileSync(fullPath, 'utf8');
        try {
            let dataArray = yaml.load(content);
            if (!Array.isArray(dataArray)) {
                dataArray = [dataArray];
            }
            for (const data of dataArray) {
                if (data && data.id) {
                    data.source_path = fullPath;
                    if (options.category) {
                        data.category = options.category;
                    }
                    results.push(data);
                }
            }
        } catch (e) {
            console.error("Error parsing", fullPath, e);
        }
    }
    return results;
}

function addDateFields(record) {
    if (record.start_date) {
        record.dateObj = new Date(record.start_date);
        record.year = record.dateObj.getFullYear();
        if (!isNaN(record.year)) {
            record.formatted_date = record.dateObj.toISOString().split('T')[0];
        } else {
            record.year = 1970;
            record.formatted_date = "Unknown Date";
        }
    } else {
        record.dateObj = new Date(0);
        record.year = 1970;
        record.formatted_date = "Unknown Date";
    }

    if (record.end_date) {
        const endObj = new Date(record.end_date);
        if (!isNaN(endObj.getTime())) {
            record.formatted_end_date = endObj.toISOString().split('T')[0];

            if (record.formatted_date !== "Unknown Date") {
                const diffMs = endObj.getTime() - record.dateObj.getTime();
                if (diffMs >= 0) {
                    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
                    record.duration = diffDays > 0 ? `${diffDays} day${diffDays !== 1 ? 's' : ''}` : "Same day";
                }
            }
        } else {
            record.formatted_end_date = "Unknown Date";
        }
    } else {
        record.formatted_end_date = "Unknown Date";
    }
}

function normalizeCampaignList(record) {
    if (!record.campaigns) {
        record.campaigns = [];
    } else if (!Array.isArray(record.campaigns)) {
        record.campaigns = [record.campaigns];
    }
}

function normalizeArtifacts(record) {
    if (!record.artifacts || !Array.isArray(record.artifacts)) {
        return;
    }
    for (const artifact of record.artifacts) {
        for (const field of ['start_date', 'end_date']) {
            if (artifact[field] instanceof Date && !isNaN(artifact[field].getTime())) {
                artifact[field] = artifact[field].toISOString().split('T')[0];
            }
        }
    }
}

function addDerivedFields(record) {
    record.name = record.target?.name || record.id;
    record.repo = record.target?.repo || "";
    record.component_type = record.target?.kind || "";
    record.cause = record.method?.cause || "";
    record.motive = record.method?.motive || "";
    record.insertion_phase = record.method?.phase || "";
    record.transitive = record.method?.transitive ?? false;
    record.impact_type = (record.impact?.types || []).join(", ");
    record.impact_user_count = record.impact?.users || 0;
    record.artifact_count = Array.isArray(record.artifacts) ? record.artifacts.length : 0;
    record.references = record.references || [];
}

function compareByDate(a, b) {
    let dateA = a.dateObj.getTime();
    let dateB = b.dateObj.getTime();
    if (isNaN(dateA)) dateA = 0;
    if (isNaN(dateB)) dateB = 0;
    return dateA - dateB;
}

function loadCampaigns() {
    const root = path.join(__dirname, '../../oss/campaigns');
    const campaigns = loadYamlRecords(root, { category: 'OSS' });
    for (const campaign of campaigns) {
        addDateFields(campaign);
        campaign.name = campaign.id;
        campaign.impact_type = (campaign.impact?.types || []).join(", ");
        campaign.impact_user_count = campaign.impact?.users || 0;
    }
    uniqueSlugs(campaigns);
    campaigns.sort(compareByDate);
    return campaigns;
}

function loadAttacks() {
    const ossRoot = path.join(__dirname, '../../oss/attacks');
    const legacyOssRoot = path.join(__dirname, '../../oss');
    const proprietaryRoot = path.join(__dirname, '../../proprietary');

    const ossDir = fs.existsSync(ossRoot) ? ossRoot : legacyOssRoot;
    const oss = loadYamlRecords(ossDir, { category: 'OSS' });
    const proprietary = loadYamlRecords(proprietaryRoot, { category: 'Proprietary' });
    const all = oss.concat(proprietary);

    const campaigns = loadCampaigns();
    const campaignByName = new Map(campaigns.map((campaign) => [campaign.id, campaign]));

    for (const attack of all) {
        addDateFields(attack);
        normalizeCampaignList(attack);
        normalizeArtifacts(attack);
        addDerivedFields(attack);
        attack.campaign_links = attack.campaigns
            .map((campaignName) => campaignByName.get(campaignName))
            .filter(Boolean)
            .map((campaign) => ({
                id: campaign.id,
                title: campaign.title,
                slug: campaign.slug,
            }));
    }

    all.sort(compareByDate);
    uniqueSlugs(all);
    return all;
}

function loadCampaignsWithMembers() {
    const campaigns = loadCampaigns();
    const attacks = loadAttacks();
    const campaignByName = new Map(campaigns.map((campaign) => [campaign.id, campaign]));

    for (const campaign of campaigns) {
        campaign.members = [];
    }

    for (const attack of attacks) {
        for (const campaignName of attack.campaigns || []) {
            const campaign = campaignByName.get(campaignName);
            if (campaign) {
                campaign.members.push(attack);
            }
        }
    }

    for (const campaign of campaigns) {
        campaign.members.sort(compareByDate);
    }

    return campaigns;
}

module.exports = {
    loadAttacks,
    loadCampaignsWithMembers,
};
