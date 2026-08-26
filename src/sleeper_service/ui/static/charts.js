// Shared wiring for the jobs-per-day / tokens-per-day panels. Both the tenant
// dashboard and a single agent's page draw the same two charts, differing only
// in the scope the server aggregated over.
const STATUS_COLORS = {succeeded: "#16a34a", failed: "#dc2626", dead_letter: "#991b1b",
  rejected: "#d97706", timeout: "#f59e0b", iteration_limit: "#f59e0b",
  budget_exceeded: "#9333ea", escalated: "#c2410c", running: "#2563eb", queued: "#6b7280"};

function jobsPerDayChart(canvasId, data) {
  return new Chart(document.getElementById(canvasId), {
    type: "bar",
    data: {labels: data.labels, datasets: data.statuses.map(s => ({
      label: s.name, data: s.counts, backgroundColor: STATUS_COLORS[s.name] || "#6b7280"}))},
    options: {scales: {x: {stacked: true}, y: {stacked: true, ticks: {precision: 0}}},
              plugins: {legend: {position: "bottom"}}, responsive: true}
  });
}

function tokensPerDayChart(canvasId, data) {
  return new Chart(document.getElementById(canvasId), {
    type: "line",
    data: {labels: data.labels, datasets: [
      {label: "tokens in", data: data.tokens_in, borderColor: "#4f46e5", tension: .25},
      {label: "tokens out", data: data.tokens_out, borderColor: "#16a34a", tension: .25}]},
    options: {plugins: {legend: {position: "bottom"}}, responsive: true,
              scales: {y: {ticks: {precision: 0}}}}
  });
}
