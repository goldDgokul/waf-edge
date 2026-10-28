FROM owasp/modsecurity-crs:nginx

# ---------------------------------------------------------------------------
# 0A.13 SSH activation rig + 0B.2 CRS baseline (ADR 0002).
#
# Base image is owasp/modsecurity-crs:nginx (Debian): nginx with
# ModSecurity v3 + OWASP CRS preinstalled. Its entrypoint renders
# ModSecurity config templates with our env overrides and activates the
# engine globally, so any vhost in conf.d is CRS-protected.
#
# IMPORTANT INTEGRATION CONSTRAINT (measured): the entrypoint RENDERS
# templates into /etc/nginx/nginx.conf and /etc/nginx/modsecurity.d/, so we
# must NOT mount anything at those paths. The main config is therefore
# BAKED into the image as /etc/nginx/templates/nginx.conf.template
# (compose may mount a per-node variant over that same template
# path); our vhost is mounted at /etc/nginx/conf.d/waf-node.conf (the
# template system owns conf.d/default.conf), and api.js feeds the njs
# content handlers.
#
# The SSH rig is DEV-ONLY activation harness (same as the nginx:alpine rig
# it replaces): production nodes are provisioned with real operator
# credentials, never a committed key; AutoAddPolicy survives only on the
# private compose network.
# ---------------------------------------------------------------------------

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server openssh-sftp-server \
    && rm -rf /var/lib/apt/lists/* \
    && ssh-keygen -A \
    && mkdir -p /run/sshd /root/.ssh \
    && chmod 700 /root/.ssh

# Dynamic modules for the CRS engine (empty-glob include in the shared
# nginx.conf tolerates stock-nginx consumers of that config).
RUN mkdir -p /etc/nginx/waf-modules.d \
    && printf 'load_module modules/ngx_http_modsecurity_module.so;\nload_module modules/ngx_http_headers_more_filter_module.so;\nload_module modules/ngx_http_js_module.so;\n' > /etc/nginx/waf-modules.d/50-crs-modules.conf

# Ship the REPO's real main config as the rendered main-config
# template. The entrypoint's envsubst pass only substitutes
# environment-variable names, and the nginx variables in this
# config ($remote_addr, $waf_rule_id, ...) are none of those, so it
# lands byte-identical at /etc/nginx/nginx.conf when the container
# starts. Doing it this way keeps plain `nginx -t` and
# `nginx -s reload` pointing at the ACTIVE config, so the SSH
# deploy chain validates the real thing.
COPY nginx.conf /etc/nginx/templates/nginx.conf.template
COPY ssh/sshd_config /etc/ssh/sshd_config
COPY ssh/authorized_keys /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys \
    && chown root:root /root/.ssh/authorized_keys

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80 8080

# Start sshd, then hand off to the stock entrypoint (which runs the
# ModSecurity template rendering + config copy steps) and nginx.
#
# CMD note (same trap as before): setting ENTRYPOINT resets CMD, so CMD is
# restated explicitly. The main config is baked as a TEMPLATE
# (/etc/nginx/templates/nginx.conf.template) which the entrypoint renders to
# /etc/nginx/nginx.conf, so the plain default config path already holds OUR
# config - no -c flag needed.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
