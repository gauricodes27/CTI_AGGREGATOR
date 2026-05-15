// IOC Pie Chart with neon glow
new Chart(document.getElementById('iocPieChart'), {
  type: 'doughnut',
  data: {
    labels: ["IPs", "Domains", "Hashes", "Malware"],
    datasets: [{
      data: [400, 250, 180, 100],
      backgroundColor: ["#06b6d4", "#f43f5e", "#fbbf24", "#22c55e"],
      borderWidth: 2,
      borderColor: "#0f1724",
      hoverOffset: 12
    }]
  },
  options: {
    plugins: {
      legend: { position: "bottom", labels: { color: "#e2e8f0" } }
    },
    animation: { animateScale: true }
  }
});

// Alerts Bar Chart
new Chart(document.getElementById('alertBarChart'), {
  type: 'bar',
  data: {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [{
      label: "Alerts",
      data: [12, 56, 34, 22],
      backgroundColor: ["#ef4444", "#f97316", "#facc15", "#22c55e"],
      borderRadius: 6
    }]
  },
  options: {
    scales: {
      x: { ticks: { color: "#e2e8f0" } },
      y: { ticks: { color: "#94a3b8" } }
    },
    plugins: {
      legend: { labels: { color: "#e2e8f0" } }
    },
    animation: { duration: 1200, easing: 'easeOutQuart' }
  }
});