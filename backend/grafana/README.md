# Grafana dashboard

The provisioned dashboard is `dashboards/dns-sinkhole.json`. It follows an operational overview layout with compact DNS KPIs, traffic and outcome trends, upstream latency percentiles and heatmap, top clients, and most-blocked domains. It defaults to a 3-hour range and refreshes every 5 seconds. Firmware batches telemetry every second. The All-device selector omits the seeded `esp32-dns-sinkhole` example identity.

The PostgreSQL datasource uses a separate `grafana_reader` login with `SELECT` access only to the dashboard's `devices` table, metrics view, and latency-only view. Its password is in the private `backend/.env.local` as `GF_DATABASE_PASSWORD`; do not copy that value into YAML or source control. The datasource is configured for `sslmode: disable` because this database is local to the Mac and listens on loopback.

## Load through Grafana provisioning

1. If Grafana is not installed, install it from Terminal with `brew install grafana`, as in [Grafana's macOS install guide](https://grafana.com/docs/grafana/latest/setup-grafana/installation/mac/).
2. From the `backend` directory, load `.env.local` and start Grafana in that terminal so it receives the database password and project provisioning paths:

   ```sh
   set -a
   source .env.local
   set +a
   "$(brew --prefix grafana)/bin/grafana" server \
     --config "$(brew --prefix)/etc/grafana/grafana.ini" \
     --homepath "$(brew --prefix grafana)/share/grafana"
   ```

   `GF_PATHS_PROVISIONING` points Grafana at this project's provisioning files. Keep that terminal open while using Grafana. The files load the dashboard and PostgreSQL datasource automatically.
3. Open `http://localhost:3000` and choose the **ESP32 DNS Sinkhole** dashboard.

Grafana's PostgreSQL datasource is built into Grafana OSS and supports datasource provisioning with the database password supplied through an environment variable. See [Grafana PostgreSQL datasource configuration](https://grafana.com/docs/grafana/latest/datasources/postgres/configure/) and [dashboard provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/).

The dashboard panels aggregate counts over the selected time range before calculating rates. This avoids averaging minute-level percentages and gives the percentage of all events in the selected range. **DNS queries blocked** is successful blocks divided by all accepted DNS queries. It measures the share of DNS traffic that matched the blocklist, so a low value can be normal when most lookups are for ordinary domains; it is not the percentage of ads removed. The Failure diagnostics row breaks service failures into upstream timeouts, upstream send errors, queue-full events, blocked-response send errors, and client-response send errors. Latency is captured on the ESP32 with microsecond timer resolution and displayed with millisecond/time units; it is upstream DNS round-trip time and excludes telemetry upload and Grafana refresh delay.
