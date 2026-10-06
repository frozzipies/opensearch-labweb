# =============================================================================
#  SOC Lab - OpenSearch + Dashboards + Seeder — single container for PaaS.
#  Give it ~1.5 GB RAM.
# =============================================================================
FROM opensearchproject/opensearch:2.19.1

USER root

# Python for the seeder
RUN yum install -y python3 && yum clean all || \
    (apt-get update && apt-get install -y python3 && rm -rf /var/lib/apt/lists/*) || true

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

RUN chown opensearch:opensearch /usr/share/opensearch/config/opensearch.yml

EXPOSE 5601
ENTRYPOINT ["/entrypoint.sh"]
