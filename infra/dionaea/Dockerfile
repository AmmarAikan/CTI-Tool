FROM dinotools/dionaea:0.11.0@sha256:6f06d0a6035c865cb60ef51bd96ff3b1f25ee4bfcd852dad3f551bc2d93464ca

COPY log_json.yaml /opt/dionaea/template/etc/dionaea/ihandlers-enabled/log_json.yaml

# The upstream default writes every debug domain to dionaea.log. A public SMB
# sensor can generate more than 100 GB per day at that level. JSON incidents
# remain the authoritative ingestion evidence, so retain only warning/error
# text diagnostics and rotate them separately on the VPS host.
RUN sed -i 's/^default\.levels=all$/default.levels=warning,error/' \
    /opt/dionaea/template/etc/dionaea/dionaea.cfg

# Dionaea's stock configuration uses paths relative to its installation root.
WORKDIR /opt/dionaea
