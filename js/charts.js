document.addEventListener("DOMContentLoaded", () => {
    if (typeof attackData === 'undefined') return;

    // Process data for charts
    const yearCounts = {};
    const langCounts = {};

    attackData.forEach(item => {
        if (item.year > 1970) {
            yearCounts[item.year] = (yearCounts[item.year] || 0) + 1;
        }
        if (item.lang) {
            langCounts[item.lang] = (langCounts[item.lang] || 0) + 1;
        }
    });

    const years = Object.keys(yearCounts).sort();
    const yearValues = years.map(y => yearCounts[y]);

    const langs = Object.keys(langCounts).sort((a,b) => langCounts[b] - langCounts[a]).slice(0, 10);
    const langValues = langs.map(l => langCounts[l]);

    // Global Chart Defaults for Monochrome
    Chart.defaults.color = '#e0e0e0';
    Chart.defaults.font.family = "'Courier Prime', monospace";

    const timelineCtx = document.getElementById('timelineChart');
    if (timelineCtx) {
        new Chart(timelineCtx, {
            type: 'bar',
            data: {
                labels: years,
                datasets: [{
                    label: 'Attacks by Year',
                    data: yearValues,
                    backgroundColor: '#ffffff',
                    borderColor: '#ffffff',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: '#333' }
                    },
                    x: {
                        grid: { color: '#333' }
                    }
                }
            }
        });
    }

    const ecosystemCtx = document.getElementById('ecosystemChart');
    if (ecosystemCtx) {
        new Chart(ecosystemCtx, {
            type: 'doughnut',
            data: {
                labels: langs,
                datasets: [{
                    label: 'Attacks by Language',
                    data: langValues,
                    backgroundColor: [
                        '#ffffff', '#e0e0e0', '#c0c0c0', '#a0a0a0', '#808080',
                        '#606060', '#404040', '#303030', '#202020', '#101010'
                    ],
                    borderColor: '#050505',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    }
});
