#pragma once

// Replace the placeholder with the PEM certificate for your own local CA.
// Do not commit a private key. Copy this file to telemetry_ca.h after setup.
#define TELEMETRY_CA_CERT_PEM R"PEM(
-----BEGIN CERTIFICATE-----
REPLACE_WITH_YOUR_LOCAL_CA_CERTIFICATE
-----END CERTIFICATE-----
)PEM"
