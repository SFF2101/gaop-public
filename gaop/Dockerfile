# GAOP v0.7.0 — durable production generation. Base image set explicitly (Supervisor no longer
# auto-provides BUILD_FROM). Stdlib-only Python; ca-certificates for Google TLS.
FROM ghcr.io/home-assistant/base:latest

RUN apk add --no-cache python3 ca-certificates && update-ca-certificates 2>/dev/null || true

# GAOP_RELEASE.json is generated into the public distribution from the exact private source
# commit; the App verifies its runtime files against it at every start (fail closed on mismatch).
COPY gaop_core.py /gaop_core.py
COPY run.sh /run.sh
COPY GAOP_RELEASE.json /GAOP_RELEASE.json
RUN chmod a+x /run.sh /gaop_core.py

LABEL \
  io.hass.version="0.7.2" \
  io.hass.type="addon" \
  io.hass.arch="aarch64|amd64"

CMD [ "/run.sh" ]
