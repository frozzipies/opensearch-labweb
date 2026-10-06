# =============================================================================
#  SOC Lab - OpenSearch + Dashboards + Seeder — single container for PaaS.
#  Debian 12 slim base. Give it ~1.5 GB RAM.
# =============================================================================
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates python3 adduser procps \
 && rm -rf /var/lib/apt/lists/*

# Create opensearch user
RUN adduser --disabled-password --gecos "" --home /usr/share/opensearch opensearch

# Download and install OpenSearch
RUN curl -sL "https://artifacts.opensearch.org/releases/bundle/opensearch/2.19.1/opensearch-2.19.1-linux-x64.tar.gz" | \
    tar -xz -C /opt/ && \
    ln -s /opt/opensearch-2.19.1 /usr/share/opensearch && \
    chown -R opensearch:opensearch /opt/opensearch-2.19.1

# Download and install OpenSearch Dashboards
RUN curl -sL "https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/2.19.1/opensearch-dashboards-2.19.1-linux-x64.tar.gz" | \
    tar -xz -C /opt/ && \
    ln -s /opt/opensearch-dashboards-2.19.1 /opt/opensearch-dashboards && \
    chown -R opensearch:opensearch /opt/opensearch-dashboards-2.19.1

# Configuration
COPY config/opensearch.yml /usr/share/opensearch/config/opensearch.yml
COPY allinone/opensearch_dashboards.yml /opt/opensearch-dashboards/config/opensearch_dashboards.yml

# Seeder + entrypoint
COPY seeder/seed.py /opt/seeder/seed.py
COPY allinone/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Fix ownership + bake /etc/hosts aliases at build time
RUN chown opensearch:opensearch /usr/share/opensearch/config/opensearch.yml \
 && chown -R opensearch:opensearch /opt/seeder \
 && mkdir -p /var/log /var/lib/opensearch && chown opensearch:opensearch /var/log /var/lib/opensearch \
 && echo "127.0.0.1 opensearch dashboards" >> /etc/hosts

USER opensearch
WORKDIR /usr/share/opensearch

EXPOSE 5601
ENTRYPOINT ["/entrypoint.sh"]
