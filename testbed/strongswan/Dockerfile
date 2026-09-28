# strongSwan peer for the IPsec capture testbed. Build context: testbed/
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      strongswan-charon strongswan-swanctl libcharon-extra-plugins \
      libstrongswan-standard-plugins libstrongswan-extra-plugins \
      iproute2 iputils-ping tcpdump procps python3 iptables \
 && rm -rf /var/lib/apt/lists/*

COPY strongswan/strongswan.conf /etc/strongswan.conf
COPY strongswan/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/traffic.py /usr/local/bin/traffic.py
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh /usr/local/bin/traffic.py \
 && chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/traffic.py

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
