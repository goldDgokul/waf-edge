FROM nginx:alpine

# ---------------------------------------------------------------------------
# 0A.13 - ONE SSH-CAPABLE NODE, so the deployment chain can be OBSERVED.
#
# This is a DEV-ONLY activation rig. The stock nginx:alpine image has no sshd,
# so the SSH transport (_ssh_deploy_sync) has never executed: it raises
# ValueError('SSH key required') before connecting, and even with a key it would
# have nothing to connect to (measured: `which sshd` -> ABSENT on both nodes).
#
# Adding openssh-server lets the API actually run the validate -> activate ->
# reload -> verify -> rollback chain for the first time, against a real nginx.
# This image is for the local development stack, NOT a production node image:
# production nodes are provisioned with real credentials by the operator, never
# with a committed key. The matching host-key policy in src/nginx_manager.py uses
# paramiko.AutoAddPolicy() (accept-any-host-key), which is fine only on the private
# compose network - do not carry it into a production node image.
# ---------------------------------------------------------------------------

RUN apk add --no-cache openssh-server openssh-sftp-server \
    && ssh-keygen -A \
    && mkdir -p /root/.ssh \
    && chmod 700 /root/.ssh

COPY ssh/sshd_config /etc/ssh/sshd_config
COPY ssh/authorized_keys /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys \
    && chown root:root /root/.ssh/authorized_keys

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80

# Start sshd, then hand off to the stock nginx entrypoint so nginx still runs
# in the foreground (its CMD is inherited from nginx:alpine).
#
# NOTE ON CMD: setting ENTRYPOINT here RESETS the CMD inherited from nginx:alpine
# to null (documented Docker behaviour), so /entrypoint.sh would call
# /docker-entrypoint.sh with no command and the stock entrypoint would exit 0 —
# the crash-loop this fix prevents. CMD is therefore re-stated explicitly.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
