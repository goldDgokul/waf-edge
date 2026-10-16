"""
Nginx Manager Module

Handles nginx configuration management and rule deployment across multiple nodes.
Enhanced security with encrypted SSH key support and comprehensive error handling.
"""

import asyncio
import httpx
import paramiko
import os
import re
import time
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from .error_handling import retry, error_recovery, CircuitBreakerConfig
from datetime import datetime
import json
import tempfile
import os
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
from loguru import logger
from pathlib import Path

# Directory that holds the AI-generated rule files. In the Docker setup this is
# the shared volume the nginx nodes mount at /etc/nginx/waf-rules, so a file
# written here is the file the nodes load. Exposed as module state (rather than
# a literal inside the deploy method) so it can be redirected in tests and
# configured per deployment.
SHARED_WAF_DIR = os.getenv("WAF_SHARED_RULES_DIR", "/app/waf-rules")

# Where the rules live on a REMOTE node reached over SSH. A separate constant from
# SHARED_WAF_DIR because the same directory is reached by different routes: the API
# container sees it as /app/waf-rules, the node sees it as /etc/nginx/waf-rules. One
# destination SHAPE, two roots.
REMOTE_WAF_RULES_DIR = "/etc/nginx/waf-rules"

# A node id becomes a DIRECTORY NAME in the rules include, so anything outside
# this set would either escape the rules root or produce a directory the vhost's
# `include .../agent-<node>/*.conf` cannot match - a rule file nginx never reads,
# which is the "success while protecting nothing" failure this module exists to
# prevent. The API validates node_id on the add-node path (SecureNginxNodeModel),
# but rules identity must NOT depend on a caller having gone through that model:
# nodes can also arrive from configuration and from the environment.
_NODE_ID_MAX_LENGTH = 64
_NODE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def validate_node_id(node_id: str) -> str:
    """
    Return node_id unchanged if it is safe to use as a directory name, else raise.

    Raising rather than sanitising is deliberate. A mangled id would still produce
    a path, and that path would be a DIFFERENT node's directory - so a deployment
    could report success while writing rules into another tenant's file. There is
    no safe rewrite of an invalid identity, so the operation must refuse.
    """
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("node_id must be a non-empty string")
    if len(node_id) > _NODE_ID_MAX_LENGTH:
        raise ValueError(
            f"node_id is {len(node_id)} characters; the limit is {_NODE_ID_MAX_LENGTH}"
        )
    if not _NODE_ID_PATTERN.fullmatch(node_id):
        raise ValueError(
            f"node_id {node_id!r} is not usable as a directory name. It must start "
            f"with a letter or digit and contain only letters, digits, dot, "
            f"underscore or hyphen - otherwise it cannot appear in the vhost's "
            f"include path and its rules would never be loaded."
        )
    if os.sep in node_id or "/" in node_id or "\\" in node_id or ".." in node_id:
        raise ValueError(
            f"node_id {node_id!r} contains a path separator or traversal sequence"
        )
    return node_id


def remote_rule_destination(node_id: str) -> str:
    """
    The destination as a POSIX path for a remote node.

    Same shape as rule_destination_for(), but with forward slashes guaranteed.
    os.path.join() uses the LOCAL separator, so on Windows it would produce
    `agent-node_1\\rules.conf` - harmless when writing to a share, wrong when the
    string is compared against a path inside an `nginx -T` dump from Linux.
    """
    return "/".join(rule_destination_for(node_id).split(os.sep))



def staging_destination_for(node_id: str) -> str:
    """
    Where a candidate goes BEFORE it has been validated.

    WHY THIS EXISTS AT ALL - the defect it removes (0A.1(c)):

    `_deploy_via_file` used to write the generated rules straight to
    `agent-<node>/rules.conf` - which is the directory the node's vhost includes:

        include /etc/nginx/waf-rules/agent-<node>/*.conf;

    and to do it with `os.replace()`, so the file appeared ATOMICALLY under the
    live name with nothing having checked it. The method then returned False and
    logged "STAGED, NOT ACTIVE", so it was honest about not ACTIVATING anything -
    but the unvalidated file was nonetheless sitting in the include-matched path,
    and the node's next legitimate reload would load it. An unvalidated candidate
    is exactly what caused the original outage this workstream exists to prevent
    (`[emerg] "if" directive is not allowed here in dynamic-node_1.conf:9`).

    The honest report and the dangerous write were two separate facts, and only the
    first had been fixed.

    THE RULE NOW: a file that has not passed a real `nginx -t` must not be reachable
    by any include glob. Staging is a sibling directory that no include matches -
    its name deliberately does not end in `.conf` - so "not yet validated" cannot
    become "loaded by accident".

    WHY THIS MATTERS MORE THAN THE HONEST REPORT DID - measured 2026-10-16.
    The old defence was "the node's next reload would fail loudly". TESTED, and it
    is FALSE in the way that matters:

        planted an invalid directive at agent-node_1/RELOAD-TEST.conf
        nginx -t          -> [emerg] unknown "x" variable ... test failed
        nginx -s reload   -> [emerg] unknown "x" variable ... EXIT CODE 0
        node afterwards   -> still serving 200

    So on a RELOAD the master discards the bad config, the old workers keep
    serving, and the only trace is a log line - the QUIETEST possible failure, not a
    loud one. On a RESTART the same config is fatal: the master cannot start, and
    `restart: unless-stopped` (docker-compose.yml, both node services) turns it into
    a crash-loop serving nothing.

    The hazard was therefore a LATENT LANDMINE, armed by whatever later caused a
    reload or restart - an operator reloading for an unrelated change, a host
    reboot, a daemon upgrade - and never by the caller who got the honest failure
    message. The report protected the one party least able to be hurt by it.

    This is deliberately a SEPARATE function from rule_destination_for(): the whole
    point is that these two paths must be able to differ. The helper chain keeps
    them in one place so no transport invents a third.
    """
    return os.path.join(
        "_staging",
        f"agent-{validate_node_id(node_id)}",
        "rules.conf.pending",
    )


# How long an unvalidated candidate may sit in staging before it is swept.
#
# WHY THIS EXISTS (found by an independent review, 2026-10-16): the staging path is
# one FIXED filename per node, so a new deploy overwrites the previous candidate -
# but nothing ever removed them, and `_staging` is on the shared volume the nodes
# mount. Left alone it accumulates one directory per node forever, and stale
# candidates are a hazard of their own: a later promotion step, or an operator
# copying "the staged file", could pick up a candidate from days ago.
#
# 24 hours is deliberately conservative: long enough that a candidate staged during
# an incident investigation is still there to inspect, short enough that nothing
# ancient survives to be mistaken for current.
STAGING_MAX_AGE_SECONDS = 24 * 60 * 60


def sweep_stale_staged_candidates(max_age_seconds: int = STAGING_MAX_AGE_SECONDS) -> int:
    """
    Delete staged candidates older than `max_age_seconds`. Returns how many went.

    Safety, so this can never become its own incident:
      - it NEVER touches the live path (only `_staging/`), so the worst it can do is
        remove a candidate that was never validated and never activated;
      - it only removes regular files, and never follows a symlink out of the tree;
      - a failure to stat or unlink one entry is logged and skipped, never raised, so
        housekeeping can never break a deployment.

    Called opportunistically after a successful stage, so it costs nothing on the
    happy path and cannot be forgotten as a separate scheduled job.
    """
    root = os.path.join(SHARED_WAF_DIR, "_staging")
    if not os.path.isdir(root):
        return 0

    now = time.time()
    removed = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    if os.path.islink(full):
                        continue
                    st = os.stat(full)
                    if not os.path.isfile(full):
                        continue
                    if now - st.st_mtime > max_age_seconds:
                        os.unlink(full)
                        removed += 1
                        logger.info(f"Swept stale staged candidate (age checked): {full}")
                except OSError as e:
                    logger.warning(f"Could not sweep {full}: {e}")
    except Exception as e:
        logger.warning(f"Staging sweep failed, continuing: {e}")
    return removed


def rule_destination_for(node_id: str) -> str:
    """
    The ONE destination for a node's generated rules, relative to the rules root.

    EVERY part of the deployment code that needs to know where a node's rules live
    builds the path from here: the file transport, the SSH transport, and the
    verifier that checks the rules were loaded. A hardcoded path in one of them was
    how a second, independent definition of the same fact survived - and it was
    only ever going to be found by a change that moved the file and left the
    verifier searching for the old name.

    (The verifier previously built its own f-string. It happened to match, and a
    mismatch would have failed safe by reporting failure rather than success - but
    two definitions of one fact is the shape of the defect this change removes, so
    the verifier now calls through the helpers below like everything else.)

    WHAT ACTUALLY HAPPENED, so nobody re-derives a wrong fix (corrected
    2026-10-15 after an independent review falsified an earlier version of this
    comment):

      - At commit b0b35b3 the Docker/file transport wrote
        `<rules_root>/dynamic-<node>.conf`, while the SSH transport wrote
        `{node.nginx_config_path}/waf_rules_auto.conf`, i.e.
        /etc/nginx/conf.d/waf_rules_auto.conf. They did NOT both write
        agent-<node>/rules.conf. An earlier version of this docstring claimed
        otherwise and was wrong.
      - The SSH transport had never actually run: it called
        tempfile.mkstemp(mode=..., delete=...), which raises TypeError, so it
        aborted before deploying anything.
      - The vhost's literal include of dynamic-node_<node>.conf was removed
        because a SECOND include of a generated file at the same scope makes the
        same batch land twice, and nginx rejects a duplicate `limit_req` by
        discarding EVERY rule in the file. That two-include state was an
        uncommitted ad-hoc edit, not a shipped revision - the failure is real and
        reproducible, but it was never what git contained.

    The shape is not a preference - it is set by the vhost include:
        include /etc/nginx/waf-rules/agent-<node>/*.conf;
    so the directory must be `agent-<node>` and the file must end in `.conf`.
    Anything else is invisible to nginx: a write that can report success while
    protecting nothing.

    Relative, not absolute, because the two transports reach the same directory
    by different routes - the API container sees it as /app/waf-rules, the node
    sees it as /etc/nginx/waf-rules, and the SSH transport reaches the remote
    copy. Each joins this to its own root.
    """
    return os.path.join(f"agent-{validate_node_id(node_id)}", "rules.conf")



@dataclass
class NginxNode:
    """Represents an nginx node in the cluster"""
    node_id: str
    hostname: str
    ssh_host: str
    ssh_port: int
    ssh_username: str
    ssh_key_path: Optional[str]
    nginx_config_path: str
    nginx_reload_command: str
    api_endpoint: Optional[str] = None
    ssh_key_passphrase: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary, excluding sensitive information"""
        return {
            'node_id': self.node_id,
            'hostname': self.hostname,
            'ssh_host': self.ssh_host,
            'ssh_port': self.ssh_port,
            'ssh_username': self.ssh_username,
            'nginx_config_path': self.nginx_config_path,
            'nginx_reload_command': self.nginx_reload_command,
            'api_endpoint': self.api_endpoint,
            'has_ssh_key': self.ssh_key_path is not None,
            'has_passphrase': self.ssh_key_passphrase is not None
        }


class SecureSSHKeyManager:
    """Manages SSH keys with encryption support"""
    
    def __init__(self, master_password: Optional[str] = None):
        self.master_password = master_password or os.getenv('WAF_SSH_MASTER_PASSWORD', '')
        self._cache = {}
        self._lock = threading.RLock()
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def cleanup_temp_keys(self):
        """Clean up temporary decrypted keys"""
        with self._lock:
            for temp_path in self._cache.values():
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp key {temp_path}: {e}")
            self._cache.clear()


class NginxManager:
    """Secure nginx configuration manager with comprehensive error handling"""
    
    def __init__(self, nodes: List[NginxNode]):
        self.nodes = {node.node_id: node for node in nodes}
        self.deployment_history = []
        self.ssh_key_manager = SecureSSHKeyManager()
        self._lock = threading.RLock()
        self.last_status_check = {}
        
        # Validate nodes on initialization
        self._validate_nodes()
    
    def _validate_nodes(self):
        """Validate node configurations"""
        for node in self.nodes.values():
            try:
                # Validate SSH key path if provided
                if node.ssh_key_path and not os.path.exists(node.ssh_key_path):
                    logger.warning(f"SSH key not found for node {node.node_id}: {node.ssh_key_path}")
                
                # Validate nginx reload command
                allowed_commands = [
                    'sudo systemctl reload nginx',
                    'sudo systemctl restart nginx', 
                    'sudo nginx -s reload',
                    'sudo service nginx reload',
                    'systemctl reload nginx',
                    'nginx -s reload'
                ]
                
                if node.nginx_reload_command not in allowed_commands:
                    logger.warning(f"Potentially unsafe nginx command for node {node.node_id}: {node.nginx_reload_command}")
                
            except Exception as e:
                logger.error(f"Node validation failed for {node.node_id}: {e}")
    
    def add_node(self, node: NginxNode):
        """Add a new node to the cluster"""
        with self._lock:
            self.nodes[node.node_id] = node
            logger.info(f"Added node to cluster: {node.node_id}")
    
    def remove_node(self, node_id: str) -> bool:
        """Remove a node from the cluster"""
        with self._lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                logger.info(f"Removed node from cluster: {node_id}")
                return True
            return False
    
    async def deploy_rules_to_all_nodes(self, nginx_config: str) -> Dict[str, bool]:
        """Deploy WAF rules to all nginx nodes with comprehensive error handling"""
        with self._lock:
            deployment_results = {}
            
            logger.info(f"Deploying rules to {len(self.nodes)} nodes...")
            
            # Validate nginx config syntax before deployment
            if not self._validate_nginx_config(nginx_config):
                logger.error("Invalid nginx configuration syntax")
                return {node_id: False for node_id in self.nodes.keys()}
            
            # Deploy to all nodes in parallel with timeout
            tasks = [
                asyncio.wait_for(
                    self._deploy_to_node(node, nginx_config),
                    timeout=30.0
                )
                for node in self.nodes.values()
            ]
            
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, node in enumerate(self.nodes.values()):
                    if isinstance(results[i], Exception):
                        deployment_results[node.node_id] = False
                        logger.error(f"Failed to deploy to {node.node_id}: {results[i]}")
                    else:
                        deployment_results[node.node_id] = results[i]
                        status = 'Success' if results[i] else 'Failed'
                        logger.info(f"Deployment to {node.node_id}: {status}")
            
            except Exception as e:
                logger.error(f"Deployment task failed: {e}")
                deployment_results = {node_id: False for node_id in self.nodes.keys()}
            
            # Record deployment
            self.deployment_history.append({
                'timestamp': datetime.now().isoformat(),
                'config_content_hash': hash(nginx_config),  # Don't store full config for security
                'config_size': len(nginx_config),
                'results': deployment_results,
                'success_count': sum(deployment_results.values()),
                'total_nodes': len(self.nodes)
            })
            
            # Keep only last 100 deployments
            if len(self.deployment_history) > 100:
                self.deployment_history = self.deployment_history[-100:]
            
            return deployment_results
    
    async def deploy_rules_to_specific_nodes(
        self, node_ids: List[str], nginx_config: str
    ) -> Dict[str, bool]:
        """
        Deploy to the named nodes ONLY. Unknown ids are refused, not skipped.

        WHY THIS EXISTS: the API's `node_ids` parameter was accepted, validated
        against a regex, and then silently ignored - both branches of the caller's
        `if request.node_ids:` called deploy_rules_to_all_nodes(). So a request to
        deploy to ONE node changed EVERY node, and the caller had no way to notice.
        In a multi-tenant product the target set is a safety boundary: a rule meant
        for one tenant's node must not reach another tenant's traffic because a
        parameter was quietly dropped.

        REFUSING ON AN UNKNOWN ID is deliberate. The tempting alternative - deploy to
        whichever ids happen to exist and ignore the rest - turns a typo into a
        silent partial deployment that still reports success. Every requested id is
        either deployed to or reported False.

        Validation order matters: the node ids are checked BEFORE any deployment, so
        an invalid request cannot leave the cluster half-changed.
        """
        with self._lock:
            logger.info(
                f"Deploying rules to {len(node_ids)} named node(s): {node_ids}"
            )

            # 1. Every requested id must exist. Refuse the whole request otherwise.
            unknown = [nid for nid in node_ids if nid not in self.nodes]
            if unknown:
                logger.error(
                    f"Refusing selective deployment: node id(s) not in this cluster: "
                    f"{unknown}. Known nodes: {sorted(self.nodes.keys())}"
                )
                return {nid: False for nid in node_ids}

            # 2. Node ids that DO exist must still be valid as directory names, since
            #    the id becomes part of a path (agent-<id>/rules.conf). validate_node_id
            #    raises rather than sanitising - a mangled id would be a DIFFERENT
            #    tenant's directory.
            try:
                for nid in node_ids:
                    validate_node_id(nid)
            except ValueError as e:
                logger.error(f"Refusing selective deployment: {e}")
                return {nid: False for nid in node_ids}

            # 3. The same syntax gate the all-nodes path applies, so the two cannot
            #    disagree about what is deployable.
            if not self._validate_nginx_config(nginx_config):
                logger.error("Invalid nginx configuration syntax")
                return {nid: False for nid in node_ids}

            targets = [self.nodes[nid] for nid in node_ids]
            # Deduplicate while preserving the caller's order, so a repeated id does
            # not deploy twice to the same node.
            seen, unique_targets = set(), []
            for n in targets:
                if n.node_id not in seen:
                    seen.add(n.node_id)
                    unique_targets.append(n)

            deployment_results: Dict[str, bool] = {}
            tasks = [
                asyncio.wait_for(
                    self._deploy_to_node(node, nginx_config), timeout=30.0
                )
                for node in unique_targets
            ]
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, node in enumerate(unique_targets):
                    if isinstance(results[i], Exception):
                        deployment_results[node.node_id] = False
                        logger.error(
                            f"Failed to deploy to {node.node_id}: {results[i]}"
                        )
                    else:
                        deployment_results[node.node_id] = results[i]
                        status = "Success" if results[i] else "Failed"
                        logger.info(f"Deployment to {node.node_id}: {status}")
            except Exception as e:
                logger.error(f"Selective deployment task failed: {e}")
                deployment_results = {nid: False for nid in node_ids}

            # Any requested id that produced no result at all is a failure, not an
            # absence - otherwise an unrecognised id vanishes from the report and the
            # caller's "every node succeeded" check passes over it.
            for nid in node_ids:
                deployment_results.setdefault(nid, False)

            self.deployment_history.append({
                'timestamp': datetime.now().isoformat(),
                'config_content_hash': hash(nginx_config),
                'config_size': len(nginx_config),
                'results': deployment_results,
                'success_count': sum(deployment_results.values()),
                'total_nodes': len(deployment_results),
                'targeted_node_ids': list(node_ids),
            })
            if len(self.deployment_history) > 100:
                self.deployment_history = self.deployment_history[-100:]

            return deployment_results

    def _validate_nginx_config(self, config: str) -> bool:
        """Enhanced nginx configuration validation with comprehensive checks"""
        try:
            logger.debug("Starting comprehensive nginx configuration validation")
            
            # 1. Basic syntax validation
            if not self._validate_basic_syntax(config):
                return False
            
            # 2. Security validation
            if not self._validate_security_directives(config):
                return False
            
            # 3. WAF-specific validation
            if not self._validate_waf_rules(config):
                return False
            
            # 4. Performance impact validation
            if not self._validate_performance_impact(config):
                logger.warning("Configuration may have performance impact")
                # Don't fail for performance warnings, just log
            
            # 5. Rule conflict detection
            conflicts = self._detect_rule_conflicts(config)
            if conflicts:
                logger.warning(f"Detected potential rule conflicts: {conflicts}")
                # Log conflicts but don't fail validation
            
            logger.info("Nginx configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Config validation error: {e}")
            return False
    
    def _validate_basic_syntax(self, config: str) -> bool:
        """Validate basic nginx syntax"""
        try:
            # Check for balanced braces
            brace_count = config.count('{') - config.count('}')
            if brace_count != 0:
                logger.error("Unbalanced braces in nginx configuration")
                return False
            
            # Check for balanced quotes
            single_quotes = config.count("'")
            double_quotes = config.count('"')
            if single_quotes % 2 != 0:
                logger.error("Unmatched single quotes in nginx configuration")
                return False
            if double_quotes % 2 != 0:
                logger.error("Unmatched double quotes in nginx configuration")
                return False
            
            # Check for proper semicolon usage
            lines = config.split('\n')
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Skip block directives and comments
                    if line.endswith('{') or line.endswith('}') or line.startswith('#'):
                        continue
                    # Most directives should end with semicolon
                    if not line.endswith(';') and not line.endswith('{'):
                        logger.warning(f"Line {i} may be missing semicolon: {line}")
            
            return True
            
        except Exception as e:
            logger.error(f"Basic syntax validation failed: {e}")
            return False
    
    def _validate_security_directives(self, config: str) -> bool:
        """Validate security directives and detect dangerous patterns"""
        try:
            # Check for dangerous directives
            dangerous_directives = [
                'include /etc/passwd', 
                'include /etc/shadow', 
                'include /etc/hosts',
                '$(',  # Command substitution
                '`',   # Command substitution
                'eval',
                'exec'
            ]
            
            for directive in dangerous_directives:
                if directive in config:
                    logger.error(f"Dangerous directive found in config: {directive}")
                    return False
            
            # Check for path traversal in include directives
            import re
            include_pattern = r'include\s+([^\s;]+)'
            includes = re.findall(include_pattern, config)
            
            for include_path in includes:
                if '..' in include_path:
                    logger.error(f"Potential path traversal in include: {include_path}")
                    return False
                if include_path.startswith('/'):
                    # Absolute paths should be from safe directories
                    safe_prefixes = ['/etc/nginx/', '/usr/share/nginx/', '/var/lib/nginx/']
                    if not any(include_path.startswith(prefix) for prefix in safe_prefixes):
                        logger.warning(f"Include path outside safe directories: {include_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Security validation failed: {e}")
            return False
    
    def _validate_waf_rules(self, config: str) -> bool:
        """Validate WAF-specific rules and patterns"""
        try:
            # Check for required WAF elements
            waf_elements = ['deny', 'return', 'if', 'limit_req']
            found_elements = [elem for elem in waf_elements if elem in config]
            
            if not found_elements:
                logger.warning("Configuration doesn't contain typical WAF elements")
                return True  # Not an error, just informational
            
            # Validate regex patterns in configuration
            import re
            regex_pattern = r'~\s*"([^"]+)"'
            regexes = re.findall(regex_pattern, config)
            
            for regex in regexes:
                try:
                    re.compile(regex)
                except re.error as e:
                    logger.error(f"Invalid regex pattern in config: {regex} - {e}")
                    return False
            
            # Check for proper rate limiting configuration
            if 'limit_req' in config:
                limit_req_pattern = r'limit_req\s+zone=(\w+)'
                zones = re.findall(limit_req_pattern, config)
                
                # Check if zones are defined
                for zone in zones:
                    zone_def_pattern = f'limit_req_zone.*zone={zone}'
                    if not re.search(zone_def_pattern, config):
                        logger.warning(f"Rate limiting zone '{zone}' used but not defined")
            
            return True
            
        except Exception as e:
            logger.error(f"WAF rules validation failed: {e}")
            return False
    
    def _validate_performance_impact(self, config: str) -> bool:
        """Validate potential performance impact of configuration"""
        try:
            performance_warnings = []
            
            # Count complex regex patterns
            import re
            complex_regex_count = len(re.findall(r'~\*?\s*"[^"]{50,}"', config))
            if complex_regex_count > 10:
                performance_warnings.append(f"Many complex regex patterns: {complex_regex_count}")
            
            # Check for nested if statements
            nested_if_count = config.count('if (') + config.count('if(')
            if nested_if_count > 20:
                performance_warnings.append(f"Many conditional statements: {nested_if_count}")
            
            # Check for rate limiting configuration
            rate_limit_count = config.count('limit_req')
            if rate_limit_count > 50:
                performance_warnings.append(f"Many rate limiting rules: {rate_limit_count}")
            
            if performance_warnings:
                logger.warning(f"Performance concerns: {', '.join(performance_warnings)}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Performance validation failed: {e}")
            return True  # Don't fail on performance validation errors
    
    def _detect_rule_conflicts(self, config: str) -> List[str]:
        """Detect potential conflicts between rules"""
        try:
            conflicts = []
            
            # Check for conflicting deny/allow rules
            import re
            
            # Extract IP addresses from deny rules
            deny_ips = re.findall(r'deny\s+([0-9.]+(?:/\d+)?)', config)
            allow_ips = re.findall(r'allow\s+([0-9.]+(?:/\d+)?)', config)
            
            # Check for overlapping IP ranges (simplified)
            for deny_ip in deny_ips:
                for allow_ip in allow_ips:
                    if deny_ip == allow_ip:
                        conflicts.append(f"IP {deny_ip} both denied and allowed")
            
            # Check for duplicate rules
            lines = [line.strip() for line in config.split('\n') if line.strip() and not line.strip().startswith('#')]
            rule_counts = {}
            for line in lines:
                if any(keyword in line for keyword in ['deny', 'return', 'limit_req']):
                    rule_counts[line] = rule_counts.get(line, 0) + 1
            
            duplicates = [rule for rule, count in rule_counts.items() if count > 1]
            if duplicates:
                conflicts.extend([f"Duplicate rule: {rule}" for rule in duplicates[:5]])  # Limit output
            
            return conflicts
            
        except Exception as e:
            logger.error(f"Conflict detection failed: {e}")
            return []
    
    async def _deploy_to_node(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration to a specific nginx node with fallback"""
        try:
            # Try file-based deployment first (for Docker environments)
            success = await self._deploy_via_file(node, nginx_config)
            if success:
                logger.debug(f"File deployment successful for {node.node_id}")
                return True
            
            # Try API-based deployment if available
            if node.api_endpoint:
                success = await self._deploy_via_api(node, nginx_config)
                if success:
                    logger.debug(f"API deployment successful for {node.node_id}")
                    return True
                else:
                    logger.warning(f"API deployment failed for {node.node_id}, falling back to SSH")
            
            # Fall back to SSH deployment
            return await self._deploy_via_ssh(node, nginx_config)
        
        except Exception as e:
            logger.error(f"Error deploying to {node.node_id}: {e}")
            return False
    
    async def _deploy_via_file(self, node: NginxNode, nginx_config: str) -> bool:
        """
        Write generated rules into the shared rules volume.

        THIS TRANSPORT CANNOT ACTIVATE RULES, AND DOES NOT CLAIM TO.

        Returning True is read by callers as "these rules are enforcing". This
        method has no way to establish that, so it returns False and says why.
        Anything else is a false success, which in a security product is the worst
        kind of wrong: an operator reads "deployed", believes every node is
        protected, and stops looking.

        Why it cannot activate, measured 2026-10-15:
          - The API container has no docker CLI and no /var/run/docker.sock, so it
            cannot reach the node's nginx. `command -v docker` -> ABSENT, verified
            live in the running waf-api container.
          - The reload it used to attempt, `docker exec <node_id> nginx -s reload`,
            cannot succeed even where docker exists: main.py builds
            node_id="node_1" while the container is named "nginx-node-1", so the
            command fails with "No such container: node_1". node_id serves two
            masters - it is also the RULES identity that must match the vhost
            include `agent-node_1/*.conf` - so it cannot simply be renamed.
          - `nginx -s reload` was being read as a validation. It is not one, and
            the precise reason is narrower than it first appears (measured):
            it returned 0 for the broken candidate because the candidate was named
            `.staged`, which the include never matched - so nginx re-read the OLD
            config and had nothing to complain about. A broken file INSIDE the
            include makes reload exit 1. Either way the exit code says nothing
            about whether NEW rules were parsed, which is what was being assumed.

        The real activation path is the SSH transport (_ssh_deploy_sync), which
        validates with `nginx -t`, reloads, and confirms with `nginx -T`. It has
        never executed successfully anywhere yet - there is no VM. Until it can
        run, this method's job is to place the rules and tell the truth.

        Rules are written to the per-node directory the vhost includes, so the
        next legitimate reload picks them up. Activation is reported as NOT
        done.
        """
        try:
            # ONE destination, shared with the SSH transport via the helper, so the
            # two can never disagree about where rules live.
            rules_file = os.path.join(SHARED_WAF_DIR, rule_destination_for(node.node_id))

            # WHERE THE CANDIDATE GOES - and why it is NO LONGER the live path.
            #
            # This used to be `rules_file`, promoted by os.replace(). That put an
            # unvalidated file into the directory the vhost includes, where the
            # node's next legitimate reload would load it. See
            # staging_destination_for() for the full account. The write is now
            # unreachable by any include glob until something has actually validated
            # it, which this transport cannot do.
            staged_file = os.path.join(
                SHARED_WAF_DIR, staging_destination_for(node.node_id)
            )
            os.makedirs(os.path.dirname(staged_file), exist_ok=True)

            # Write to a temporary name and promote by rename, so a reader never
            # sees a half-written file. The name does not end in `.conf`, so it is
            # not matched by the vhost include `agent-<node>/*.conf` - a partial
            # write can never be loaded as configuration.
            #
            # A UNIQUE name per attempt: a fixed name means two concurrent deploys
            # to the same node overwrite each other's candidate.
            tmp_file = f"{staged_file}.{os.getpid()}.{threading.get_ident()}.tmp"
            try:
                with open(tmp_file, "w") as f:
                    f.write(f"# WAF rules for {node.node_id}\n")
                    f.write(f"# Generated at {datetime.now().isoformat()}\n\n")
                    f.write(nginx_config)
                    f.flush()
                    # Flush to disk before the rename, so a crash cannot leave a
                    # torn file under the staged name.
                    os.fsync(f.fileno())
                os.replace(tmp_file, staged_file)
            finally:
                if os.path.exists(tmp_file):
                    os.unlink(tmp_file)

            logger.warning(
                f"Rules for {node.node_id} were STAGED to {staged_file} and are "
                f"NOT ACTIVE. This transport cannot validate or reload nginx (no "
                f"nginx binary, no docker CLI and no docker socket in this "
                f"container), so it cannot establish that these rules are loadable, "
                f"let alone in force. The candidate is deliberately NOT placed in "
                f"{rules_file}, which is the path the node's vhost includes: an "
                f"unvalidated file there would be loaded by the next legitimate "
                f"reload - the exact failure this workstream exists to prevent. "
                f"Reporting failure so no caller believes these rules protect "
                f"traffic. Real activation requires the SSH path."
            )

            # Housekeeping on the happy path, so it cannot be forgotten as a
            # separate scheduled job. Best-effort: the sweep swallows its own
            # errors, and it only ever touches _staging/.
            swept = sweep_stale_staged_candidates()
            if swept:
                logger.info(f"Swept {swept} stale staged candidate(s)")

            return False

        except Exception as e:
            logger.error(f"Writing rules for {node.node_id} failed: {e}")
            return False

    async def _deploy_via_api(self, node: NginxNode, nginx_config: str) -> bool:
        """
        REMOVED FROM THE SUCCESS PATH IN v7.x (0A.2 / 0A.4 correction).

        WHAT THIS USED TO DO, and why it was wrong:

            if response.status_code == 200:
                result = response.json()
                return result.get('success', False)

        It returned the REMOTE's own claim of success. Nothing here checked that any
        rule became active: no `nginx -t`, no `nginx -T`, no observation of behaviour.
        A node agent that replied {"success": true} while deploying nothing made this
        method return True, and the caller read that as "these rules are enforcing".
        Measured consequence: it was the one code path that could report a deployment
        as successful WITHOUT VALIDATING ANYTHING - which is precisely what items
        0A.2 and 0A.4 claim cannot happen ("remove the unconditional success return";
        "never return success for a deployment that did not take effect").

        Why it was not caught earlier: it was unreachable in this Docker stack
        (`api_endpoint` is None for compose-built nodes, and no service in the stack
        implements `/api/config/deploy`), so no test and no manual run ever exercised
        it. An unreachable hole is still a hole: `POST /api/nodes/add` accepts an
        api_endpoint, at which point this path becomes live.

        THE RULE THIS METHOD NOW FOLLOWS: a transport may only report success if it
        can itself establish that the rules are in force. This one cannot - it has no
        access to the node's nginx. It therefore reports failure and says why, the
        same honest refusal the file transport makes.

        Kept (not deleted) so that an operator adding an api_endpoint is told plainly
        that the capability was withdrawn rather than silently skipped, and so that
        restoring it means writing a real verification step alongside it.
        """
        logger.error(
            f"API deployment to {node.node_id} ({node.api_endpoint}) REFUSED: this "
            f"transport cannot verify that rules became active - it would have to "
            f"take the remote's word for it. Previously it did, and returned that "
            f"claim as success. Rules are NOT deployed through this path. Use the "
            f"SSH transport (which runs nginx validation and verification) or the "
            f"file transport (which stages and reports truthfully)."
        )
        return False

    async def _deploy_via_ssh(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration via SSH with enhanced security"""
        try:
            # Run SSH deployment in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._ssh_deploy_sync, node, nginx_config
            )
        except Exception as e:
            logger.error(f"SSH deployment failed for {node.node_id}: {e}")
            return False
    
    @retry(max_attempts=2, backoff_strategy="fixed", base_delay=2.0)
    def _ssh_deploy_sync(self, node: NginxNode, nginx_config: str) -> bool:
        """Synchronous SSH deployment with enhanced validation and rollback"""
        ssh = None
        temp_config_path = None
        backup_path = None
        deployed_successfully = False
        
        try:
            logger.info(f"Starting deployment to node {node.node_id}")
            
            # Initialize SSH client with security settings
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with timeout and retries
            if node.ssh_key_path:
                if os.path.exists(node.ssh_key_path):
                    key_stat = os.stat(node.ssh_key_path)
                    if key_stat.st_mode & 0o077:
                        logger.warning(f"SSH key has overly permissive permissions: {node.ssh_key_path}")
                
                ssh.connect(
                    hostname=node.ssh_host,
                    port=node.ssh_port,
                    username=node.ssh_username,
                    key_filename=node.ssh_key_path,
                    timeout=30,
                    banner_timeout=30,
                    auth_timeout=30
                )
            else:
                raise ValueError(f"SSH key required for node {node.node_id}")
            
            # Create secure temporary file for configuration
            # Create secure temporary file for configuration.
            #
            # tempfile.mkstemp() takes (suffix, prefix, dir, text). The previous
            # call passed mode='w' and delete=False, which are not parameters of
            # this function, so it raised TypeError EVERY time. That aborted
            # _ssh_deploy_sync before any deployment code ran, which is why this
            # path has never actually deployed anything.
            temp_fd, temp_config_path = tempfile.mkstemp(suffix='.conf', text=True)
            try:
                with os.fdopen(temp_fd, 'w') as temp_file:
                    temp_file.write(nginx_config)
                
                os.chmod(temp_config_path, 0o600)
                
                # Deployment with validation and guaranteed cleanup.
                #
                # THREE THINGS THIS MUST GET RIGHT:
                #
                # 1. NO CROSS-NODE LEAK. Both edge nodes mount the same host
                #    directory. A wildcard over a SHARED directory means node A
                #    loads node B's rules - verified live. Each node therefore gets
                #    its OWN subdirectory, included only by that node's vhost.
                #
                # 2. THE CANDIDATE MUST ACTUALLY BE PARSED BY `nginx -t`. A
                #    `.staged` file is NOT matched by a `*.conf` include, so the
                #    test would only re-check the CURRENT config and the candidate's
                #    first real validation would happen after it was already live.
                #    The candidate is therefore written to the live name so the test
                #    genuinely parses it.
                #
                # 3. FAILURE MUST NOT LEAVE THE NODE BROKEN. The candidate is
                #    briefly in the live path - bounded by the validation window -
                #    and on ANY failure, including a FIRST deploy where there is no
                #    backup, the previous state is restored. The node is never left
                #    unable to reload or restart.
                #
                # The directory is deliberately NOT node.nginx_config_path: that
                # defaults to /etc/nginx/conf.d, included at http scope, and the
                # generated rules contain `if`, legal only in server/location.
                # Writing there reproduces the 0A.1 outage.
                # One destination rule for every transport. Built from the same
                # helper the file transport and the verifier use, in POSIX form, so
                # no two parts of the code can disagree about where rules live.
                final_path = f"{REMOTE_WAF_RULES_DIR}/{remote_rule_destination(node.node_id)}"
                rules_dir = final_path.rsplit("/", 1)[0]
                backup_path = None

                try:
                    self._ensure_remote_dir(ssh, rules_dir)

                    sftp = ssh.open_sftp()
                    try:
                        # Back up the current active file, if any.
                        try:
                            backup_path = f"{final_path}.backup.{int(datetime.now().timestamp())}"
                            sftp.rename(final_path, backup_path)
                            logger.debug(f"Backed up current rules to {backup_path}")
                        except (IOError, OSError) as exc:
                            # First deploy: nothing to back up. paramiko raises
                            # IOError(ENOENT), which IS a FileNotFoundError, but
                            # both are caught so the intent survives any transport.
                            backup_path = None
                            logger.debug(f"No existing rules to back up ({exc})")

                        # Place the candidate so that `nginx -t` really parses it.
                        sftp.put(temp_config_path, final_path)
                        sftp.chmod(final_path, 0o644)
                        logger.debug(f"Placed candidate at {final_path} for validation")

                    finally:
                        sftp.close()

                    # Validate the COMPLETE candidate with the real nginx test.
                    logger.debug(f"Testing nginx configuration on {node.node_id}")
                    nginx_test_result = self._test_nginx_config_on_node(ssh, node)

                    if not nginx_test_result['success']:
                        error_output = nginx_test_result.get('error', 'unknown error')
                        logger.error(
                            f"REJECTED: candidate for {node.node_id} failed validation: "
                            f"{error_output}"
                        )
                        return False

                    # Reload nginx with validation
                    logger.debug(f"Reloading nginx on {node.node_id}")
                    reload_result = self._reload_nginx_with_validation(ssh, node)

                    if not reload_result['success']:
                        logger.error(
                            f"Nginx reload failed on {node.node_id}: {reload_result['error']}"
                        )
                        return False

                    # Verify the rules are ACTUALLY LOADED, not merely on disk.
                    verification_result = self._verify_deployment(ssh, node, nginx_config)
                    if not verification_result['success']:
                        logger.error(
                            f"Deployment verification failed on {node.node_id}: "
                            f"{verification_result['error']}"
                        )
                        return False

                    deployed_successfully = True
                    logger.info(
                        f"Deployed and verified ACTIVE on {node.node_id}: "
                        f"{verification_result.get('message', '')}"
                    )
                    self._cleanup_old_backups(ssh, node, final_path)
                    return True

                finally:
                    # Restore the previous state if we did not finish successfully.
                    # This runs on EVERY exit path, including exceptions, so an
                    # invalid or half-applied candidate can never be left behind.
                    if not deployed_successfully:
                        self._restore_previous_config(
                            ssh, node, final_path, backup_path
                        )

            finally:
                # Clean up temporary config file
                if temp_config_path and os.path.exists(temp_config_path):
                    os.unlink(temp_config_path)
        
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for {node.node_id}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH connection failed for {node.node_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"SSH deployment error for {node.node_id}: {e}")
            return False
        
        finally:
            # Clean up resources
            if ssh:
                ssh.close()
            if temp_config_path and os.path.exists(temp_config_path):
                os.unlink(temp_config_path)

    def _test_nginx_config_on_node(self, ssh, node: NginxNode) -> Dict[str, any]:
        """Test nginx configuration on remote node"""
        try:
            stdin, stdout, stderr = ssh.exec_command("nginx -t", timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code == 0:
                return {'success': True, 'message': 'Configuration test passed'}
            else:
                error_output = stderr.read().decode().strip()
                return {'success': False, 'error': error_output}
                
        except Exception as e:
            return {'success': False, 'error': f"Failed to test configuration: {str(e)}"}

    def _reload_nginx_with_validation(self, ssh, node: NginxNode) -> Dict[str, any]:
        """Reload nginx with validation on remote node"""
        try:
            # First test configuration again before reloading
            test_result = self._test_nginx_config_on_node(ssh, node)
            if not test_result['success']:
                return test_result
            
            # Reload nginx
            stdin, stdout, stderr = ssh.exec_command(node.nginx_reload_command, timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code == 0:
                # Verify nginx is still running after reload
                stdin, stdout, stderr = ssh.exec_command("pgrep nginx", timeout=10)
                nginx_running = stdout.channel.recv_exit_status() == 0
                
                if nginx_running:
                    return {'success': True, 'message': 'Nginx reloaded successfully'}
                else:
                    return {'success': False, 'error': 'Nginx stopped after reload'}
            else:
                error_output = stderr.read().decode().strip()
                return {'success': False, 'error': f"Reload failed: {error_output}"}
                
        except Exception as e:
            return {'success': False, 'error': f"Failed to reload nginx: {str(e)}"}

    def _verify_deployment(self, ssh, node: NginxNode, expected_config: str) -> Dict[str, any]:
        """
        Verify the expected rules are LOADED, and loaded FROM OUR FILE.

        Two weaknesses this closes:

        1. The previous implementation ran `cat` on the rule file and compared the
           text with what was uploaded. That proves the file was written -
           "staged" - and it reported that as a successful deployment. The question
           that matters is whether nginx is SERVING the rules, so this uses
           `nginx -T`, which dumps the configuration as loaded.

        2. Searching the WHOLE dump is not enough either. The generator emits
           `limit_req zone=waf_dynamic burst=5 nodelay;`, and the node's own
           dynamic-<node>.conf already contains that exact line, so a
           rate-limit-only batch would "verify" as active even if our file did not
           exist. `nginx -T` labels each section with
           `# configuration file <path>:`, so the expected directives are checked
           only within OUR file's section.

        It also no longer accepts a match on any single line: every expected
        directive must be present.
        """
        try:
            stdin, stdout, stderr = ssh.exec_command("nginx -T", timeout=30)
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                return {
                    'success': False,
                    'error': 'nginx -T failed; cannot confirm the loaded configuration'
                }

            dump = stdout.read().decode()
            # Our file is the one for this node's own directory.
            #
            # Built from the same helper every other transport uses, so a change to
            # the destination shape cannot leave verification looking for a path
            # that no longer exists. Previously this was a hardcoded f-string - it
            # happened to match, but it was a second, independent definition of the
            # same fact, which is the shape of the defect this whole change removes.
            # (It failed safe: a mismatch reports failure rather than success. But
            # "fails safe" is not the same as "consistent".)
            our_file = f"{REMOTE_WAF_RULES_DIR}/{remote_rule_destination(node.node_id)}"
            section = self._extract_loaded_section(dump, our_file)

            if section is None:
                return {
                    'success': False,
                    'error': (
                        f"{our_file} does not appear in the loaded configuration, "
                        f"so none of its rules are in force"
                    )
                }

            expected_lines = [
                line.strip() for line in expected_config.split('\n')
                if line.strip() and not line.strip().startswith('#')
            ]
            if not expected_lines:
                return {
                    'success': False,
                    'error': 'No expected directives to verify'
                }

            # EXACT LINE MATCH, NOT SUBSTRING.
            #
            # This was `if line not in section`, a substring test. Measured
            # consequence: an expected directive `deny 1.2.3.4;` was satisfied by a
            # loaded line `deny 1.2.3.45;`, because the shorter string occurs inside
            # the longer one. The verifier would have reported "all expected
            # directives are loaded" while the rule the operator asked for was not
            # in force - the same false-success class as the old "any line survived"
            # weakness this method was rewritten to remove, one notch down.
            #
            # Comparing whole lines removes it. nginx re-emits source lines verbatim
            # in `nginx -T`, so a directive the operator expected appears as its own
            # line; if it does not, it is not loaded.
            section_lines = {ln.strip() for ln in section.split('\n') if ln.strip()}
            missing = [line for line in expected_lines if line not in section_lines]

            if missing:
                return {
                    'success': False,
                    'error': (
                        f'{len(missing)} of {len(expected_lines)} expected directives '
                        f'are NOT loaded from {our_file} (first: {missing[0]})'
                    )
                }

            return {
                'success': True,
                'message': (
                    f'All {len(expected_lines)} expected directives are loaded '
                    f'from {our_file}'
                )
            }

        except Exception as e:
            return {'success': False, 'error': f"Failed to verify deployment: {str(e)}"}

    @staticmethod
    def _extract_loaded_section(dump: str, path: str):
        """
        Return the part of an `nginx -T` dump that came from `path`, or None.

        `nginx -T` prefixes each included file's contents with a line of the form
        `# configuration file <path>:`. The section runs until the next such
        marker.
        """
        marker = f"# configuration file {path}:"
        start = dump.find(marker)
        if start == -1:
            return None

        body_start = start + len(marker)
        next_marker = dump.find("# configuration file ", body_start)
        if next_marker == -1:
            return dump[body_start:]
        return dump[body_start:next_marker]

    def _ensure_remote_dir(self, ssh, remote_dir: str):
        """Create a remote directory if it does not exist (idempotent)."""
        stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {remote_dir}", timeout=30)
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            error_output = stderr.read().decode().strip()
            raise IOError(f"Could not create {remote_dir}: {error_output}")

    def _restore_previous_config(self, ssh, node: NginxNode, final_path: str, backup_path):
        """
        Put the node back the way it was after a failed deployment.

        This is the safety net that makes a FIRST deploy safe. Previously the
        rollback was guarded by `if backup_path:` and a first deploy has no backup,
        so a rejected candidate stayed in the live include path and every later
        `nginx -t` on that node failed - leaving it unable to reload or restart.
        That is the same outage class the product exists to prevent.

        Two cases:
          - There was a previous file: rename the backup over the candidate.
          - There was not: remove the candidate, so the node returns to having no
            agent rules (which is a valid state, because the vhost include is a
            wildcard over a per-node directory).
        """
        try:
            sftp = ssh.open_sftp()
            try:
                if backup_path:
                    # paramiko documents standard RENAME as requiring the target
                    # not to exist, so remove the candidate first, then rename.
                    try:
                        sftp.remove(final_path)
                    except (IOError, OSError):
                        pass  # Already gone; nothing to remove.
                    sftp.rename(backup_path, final_path)
                    logger.info(
                        f"Restored previous rules on {node.node_id} from {backup_path}"
                    )
                else:
                    try:
                        sftp.remove(final_path)
                        logger.info(
                            f"Removed rejected candidate from {node.node_id}; "
                            f"the node has no agent rules, which is a valid state"
                        )
                    except (IOError, OSError) as exc:
                        logger.warning(
                            f"Could not remove candidate {final_path}: {exc}"
                        )
            finally:
                sftp.close()
        except Exception as e:
            # Never let the safety net itself raise over the real failure.
            logger.error(
                f"COULD NOT RESTORE {node.node_id} after a failed deployment: {e}. "
                f"{final_path} may need manual attention."
            )

    def _rollback_config(self, ssh, node: NginxNode, backup_path: str, current_path: str):
        """Rollback configuration to previous version"""
        try:
            logger.warning(f"Rolling back configuration on {node.node_id}")
            
            # Restore backup
            sftp = ssh.open_sftp()
            try:
                sftp.rename(backup_path, current_path)
                logger.info(f"Restored backup from {backup_path}")
            finally:
                sftp.close()
            
            # Test and reload with backup
            test_result = self._test_nginx_config_on_node(ssh, node)
            if test_result['success']:
                reload_result = self._reload_nginx_with_validation(ssh, node)
                if reload_result['success']:
                    logger.info(f"Successfully rolled back configuration on {node.node_id}")
                else:
                    logger.error(f"Failed to reload after rollback on {node.node_id}: {reload_result['error']}")
            else:
                logger.error(f"Backup configuration also invalid on {node.node_id}: {test_result['error']}")
                
        except Exception as e:
            logger.error(f"Failed to rollback configuration on {node.node_id}: {e}")

    def _cleanup_old_backups(self, ssh, node: NginxNode, config_path: str):
        """Clean up old backup files, keeping only the last 5"""
        try:
            config_dir = os.path.dirname(config_path)
            config_name = os.path.basename(config_path)
            
            # List backup files
            stdin, stdout, stderr = ssh.exec_command(f"ls {config_dir}/{config_name}.backup.* 2>/dev/null | sort -r", timeout=30)
            backup_files = stdout.read().decode().strip().split('\n')
            
            # Keep only the 5 most recent backups
            if len(backup_files) > 5 and backup_files[0]:  # Check if we have actual files
                files_to_remove = backup_files[5:]
                for backup_file in files_to_remove:
                    if backup_file.strip():
                        ssh.exec_command(f"rm -f {backup_file.strip()}", timeout=10)
                
                logger.debug(f"Cleaned up {len(files_to_remove)} old backup files on {node.node_id}")
                
        except Exception as e:
            logger.debug(f"Failed to cleanup old backups on {node.node_id}: {e}")  # Non-critical error
    
    async def check_node_status(self, node_id: str) -> Dict[str, any]:
        """Check the status of a specific nginx node with enhanced monitoring"""
        if node_id not in self.nodes:
            return {'error': f'Node {node_id} not found'}
        
        node = self.nodes[node_id]
        status = {
            'node_id': node_id,
            'hostname': node.hostname,
            'timestamp': datetime.now().isoformat(),
            'nginx_running': False,
            'config_valid': False,
            'last_deployment': None,
            'error': None
        }
        
        try:
            # Check via API if available
            if node.api_endpoint:
                api_status = await self._check_status_via_api(node)
                status.update(api_status)
            else:
                # Fall back to SSH check
                ssh_status = await self._check_status_via_ssh(node)
                status.update(ssh_status)
            
            # Add deployment history
            for deployment in reversed(self.deployment_history):
                if node_id in deployment['results']:
                    status['last_deployment'] = {
                        'timestamp': deployment['timestamp'],
                        'success': deployment['results'][node_id]
                    }
                    break
            
            # Cache status
            self.last_status_check[node_id] = status
            
        except Exception as e:
            logger.error(f"Status check failed for {node_id}: {e}")
            status['error'] = str(e)
        
        return status
    
    async def _check_status_via_api(self, node: NginxNode) -> Dict:
        """Check node status via API"""
        try:
            timeout = httpx.Timeout(10.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(f"{node.api_endpoint}/api/status")
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'nginx_running': data.get('nginx_running', False),
                        'config_valid': data.get('config_valid', False),
                        'api_available': True
                    }
                else:
                    return {
                        'api_available': False,
                        'error': f'API returned status {response.status_code}'
                    }
        except Exception as e:
            return {
                'api_available': False,
                'error': f'API check failed: {str(e)}'
            }
    
    async def _check_status_via_ssh(self, node: NginxNode) -> Dict:
        """Check node status via SSH"""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._ssh_status_check_sync, node
            )
        except Exception as e:
            return {
                'ssh_available': False,
                'error': f'SSH check failed: {str(e)}'
            }
    
    def _ssh_status_check_sync(self, node: NginxNode) -> Dict:
        """Synchronous SSH status check"""
        ssh = None
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            if node.ssh_key_path:
                ssh.connect(
                    hostname=node.ssh_host,
                    port=node.ssh_port,
                    username=node.ssh_username,
                    key_filename=node.ssh_key_path,
                    timeout=15
                )
            else:
                raise ValueError("SSH key required")
            
            # Check nginx process
            stdin, stdout, stderr = ssh.exec_command("pgrep nginx", timeout=10)
            nginx_running = stdout.channel.recv_exit_status() == 0
            
            # Check config validity
            stdin, stdout, stderr = ssh.exec_command("nginx -t", timeout=10)
            config_valid = stdout.channel.recv_exit_status() == 0
            
            return {
                'nginx_running': nginx_running,
                'config_valid': config_valid,
                'ssh_available': True
            }
            
        except Exception as e:
            return {
                'ssh_available': False,
                'error': str(e)
            }
        
        finally:
            if ssh:
                ssh.close()
    
    async def get_cluster_status(self) -> Dict[str, any]:
        """Get status of all nodes in the cluster"""
        with self._lock:
            cluster_status = {
                'timestamp': datetime.now().isoformat(),
                'total_nodes': len(self.nodes),
                'nodes': {},
                'summary': {
                    'online': 0,
                    'offline': 0,
                    'error': 0
                }
            }
            
            # Check all nodes in parallel
            tasks = [
                self.check_node_status(node_id)
                for node_id in self.nodes.keys()
            ]
            
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, node_id in enumerate(self.nodes.keys()):
                    if isinstance(results[i], Exception):
                        cluster_status['nodes'][node_id] = {
                            'error': str(results[i])
                        }
                        cluster_status['summary']['error'] += 1
                    else:
                        status = results[i]
                        cluster_status['nodes'][node_id] = status
                        
                        if status.get('nginx_running') and status.get('config_valid'):
                            cluster_status['summary']['online'] += 1
                        else:
                            cluster_status['summary']['offline'] += 1
                
            except Exception as e:
                logger.error(f"Cluster status check failed: {e}")
                cluster_status['error'] = str(e)
            
            return cluster_status
    
    def get_deployment_history(self, limit: int = 10) -> List[Dict]:
        """Get recent deployment history"""
        with self._lock:
            return self.deployment_history[-limit:] if limit else self.deployment_history.copy()
    
    def cleanup_resources(self):
        """Clean up resources (call on shutdown)"""
        try:
            self.ssh_key_manager.cleanup_temp_keys()
            logger.info("Nginx manager resources cleaned up")
        except Exception as e:
            logger.error(f"Failed to cleanup nginx manager resources: {e}")
