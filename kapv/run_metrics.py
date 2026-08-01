from prometheus_client import start_http_server, Gauge
import time

# Define metrics
attack_paths_gauge = Gauge('kapv_attack_paths',  'Attack paths found')
misconfigs_gauge   = Gauge('kapv_misconfigs',     'Misconfigurations')
top_risk_gauge     = Gauge('kapv_top_risk_score', 'Top risk score')
cycles_gauge       = Gauge('kapv_cycles',         'Privilege cycles')

# Set your KAPV results here
attack_paths_gauge.set(6)
misconfigs_gauge.set(29)
top_risk_gauge.set(27.3)
cycles_gauge.set(3)

# Start server
start_http_server(8001)
print("Prometheus metrics running at:")
print("http://localhost:8001/metrics")
print("Press Ctrl+C to stop")

# Stay alive forever
while True:
    time.sleep(10)