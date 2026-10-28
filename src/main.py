"""
Main API Module

FastAPI-based API for the nginx WAF AI system with comprehensive security.
"""

import asyncio
import ipaddress
import json
import os
import ssl
import threading
import traceback
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Dict, Optional, Any

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Response, status, Request, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from loguru import logger
from pydantic import BaseModel

import slowapi

# Note: slowapi might not be installed, implement custom rate limiting if needed
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    logger.warning("slowapi not available, rate limiting disabled")
    RATE_LIMITING_AVAILABLE = False

# Import our modules
from .auth import auth_manager, require_admin, require_operator, require_viewer
from .validation import (
    SecureNginxNodeModel, SecureTrainingRequest, SecureRuleDeploymentRequest,
    UserManagementRequest, LoginRequest, ApiKeyRequest, ValidationError
)
from .config import config
from .traffic_collector import TrafficCollector, HttpRequest
from .ml_engine import MLEngine, RealTimeProcessor, ThreatPrediction, is_threat
from .waf_rule_generator import WAFRuleGenerator, WAFRule, RuleOptimizer
from .nginx_manager import NginxManager, NginxNode
from .security_middleware import SecurityMiddleware, is_ip_whitelisted
from .error_handling import error_recovery, degradation_manager, CircuitBreakerConfig
from .training_data_generator import TrainingDataGenerator


# 0A.6-H2: behind the control panel's nginx, every browser user shares the
# panel container's IP, so keying the limiter on request.client.host
# collapses the whole panel into one rate-limit bucket. The panel proxy
# already forwards the real client in X-Real-IP; that header is trusted
# ONLY when the direct TCP peer really is the configured proxy container
# (resolved by Docker DNS and cached), so a direct caller cannot rotate
# buckets by forging the header.
import socket as _socket
import time as _time

_trusted_proxy_names = [
    name.strip()
    for name in os.getenv("WAF_TRUSTED_PROXY_HOSTS", "control-panel").split(",")
    if name.strip()
]
_trusted_proxy_cache = {"resolved_at": 0.0, "ips": frozenset()}
_TRUSTED_PROXY_TTL_SECONDS = 30.0


def _trusted_proxies() -> frozenset:
    now = _time.monotonic()
    if now - _trusted_proxy_cache["resolved_at"] < _TRUSTED_PROXY_TTL_SECONDS:
        return _trusted_proxy_cache["ips"]
    resolved = set()
    for name in _trusted_proxy_names:
        try:
            for info in _socket.getaddrinfo(name, None, proto=_socket.IPPROTO_TCP):
                resolved.add(info[4][0])
        except (_socket.gaierror, OSError):
            logger.debug(f"Trusted proxy host not resolvable here: {name}")
    _trusted_proxy_cache["resolved_at"] = now
    _trusted_proxy_cache["ips"] = frozenset(resolved)
    return _trusted_proxy_cache["ips"]


def real_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if peer and peer in _trusted_proxies():
        forwarded = request.headers.get("x-real-ip", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return peer


# Initialize rate limiter if available
if RATE_LIMITING_AVAILABLE:
    limiter = Limiter(key_func=real_client_ip)
else:
    limiter = None
# Custom rate limiting decorator when slowapi is not available
def rate_limit(limit: str):
    def decorator(func):
        if RATE_LIMITING_AVAILABLE:
            return limiter.limit(limit)(func)
        return func
    return decorator

# Thread-safe locks for global variables and state management
processing_lock = threading.RLock()  # Reentrant lock for nested calls
component_lock = threading.RLock()  # Reentrant lock for component management
state_lock = threading.RLock()  # Lock for shared state variables

# System state with proper synchronization
system_state = {
    'is_processing': False,
    'components_initialized': False,
    'last_error': None,
    'startup_time': None,
    'shutdown_requested': False
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Enhanced lifespan context manager with comprehensive error handling"""
    try:
        # Startup
        logger.info("Starting Nginx WAF AI system...")
        
        with state_lock:
            system_state['startup_time'] = datetime.now()
            system_state['shutdown_requested'] = False
        
        await startup_components()
        
        with state_lock:
            system_state['components_initialized'] = True
            
        logger.info("System startup completed successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Critical error during system startup: {e}")
        with state_lock:
            system_state['last_error'] = str(e)
        # Still yield to allow FastAPI to start, but mark system as unhealthy
        yield
        
    finally:
        # Shutdown
        try:
            logger.info("Shutting down Nginx WAF AI system...")
            
            with state_lock:
                system_state['shutdown_requested'] = True
                
            await shutdown_components()
            logger.info("System shutdown completed successfully")
            
        except Exception as e:
            logger.error(f"Error during system shutdown: {e}")
            with state_lock:
                system_state['last_error'] = str(e)


# 0A.6: OpenAPI schema and docs pages are not served at all. The schema
# previously disclosed the whole private route table on a public path.
app = FastAPI(
    title="Nginx WAF AI",
    description="Real-time machine learning WAF rule generator for nginx",
    version="0.1.0",
    lifespan=lifespan,
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)

# CORS middleware configuration for development and production
# 0A.6: the origin allowlist comes from config (WAF_CORS_ORIGINS env). The
# previous permissive fallback list granted credentialed requests from the
# "null" origin (sandboxed frames) and file:// — both removed.
cors_origins = config.security.cors_origins or []

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Add security middleware with proper exclusions - TEMPORARILY DISABLED
# app.add_middleware(
#     SecurityMiddleware,
#     rate_limit_requests=config.security.rate_limit_requests,
#     rate_limit_window=config.security.rate_limit_window,
#     enable_dos_protection=True,
#     enable_input_validation=True,
#     max_request_size=10 * 1024 * 1024,  # 10MB
#     enable_honeypot=True
# )

# Add rate limiting if available
if RATE_LIMITING_AVAILABLE:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Trusted host middleware for production security
if not config.api_debug:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", config.api_host, "waf-api", "nginx-node-1", "nginx-node-2"]
    )

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    # Log all incoming requests for debugging
    logger.info(f"Incoming request: {request.method} {request.url} from {request.client.host if request.client else 'unknown'}")
    
    response = await call_next(request)
    
    if config.security.enable_security_headers:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    logger.info(f"Response status: {response.status_code}")
    return response

# Import metrics module to centralize Prometheus metrics
from . import metrics

# Global components with thread safety - use proper synchronization
class ComponentManager:
    """Thread-safe component manager"""
    def __init__(self):
        self._lock = threading.RLock()
        self._components = {
            'traffic_collector': None,
            'ml_engine': None,
            'real_time_processor': None,
            'waf_rule_generator': None,
            'nginx_manager': None,
            'rule_optimizer': None
        }
        self._component_status = {
            'traffic_collector': {'status': 'stopped', 'last_error': None},
            'ml_engine': {'status': 'stopped', 'last_error': None},
            'real_time_processor': {'status': 'stopped', 'last_error': None},
            'waf_rule_generator': {'status': 'stopped', 'last_error': None},
            'nginx_manager': {'status': 'stopped', 'last_error': None},
            'rule_optimizer': {'status': 'stopped', 'last_error': None}
        }
    
    def get_component(self, name: str):
        with self._lock:
            return self._components.get(name)
    
    def set_component(self, name: str, component):
        with self._lock:
            self._components[name] = component
            if component is not None:
                self._component_status[name]['status'] = 'running'
                self._component_status[name]['last_error'] = None
    
    def get_status(self, name: str = None):
        with self._lock:
            if name:
                return self._component_status.get(name, {})
            return self._component_status.copy()
    
    def set_error(self, name: str, error: str):
        with self._lock:
            if name in self._component_status:
                self._component_status[name]['status'] = 'error'
                self._component_status[name]['last_error'] = error
    
    def shutdown_all(self):
        with self._lock:
            for name in self._components:
                self._components[name] = None
                self._component_status[name]['status'] = 'stopped'

# Global component manager instance
component_manager = ComponentManager()

# Helper functions for safe component access
def get_ml_engine() -> Optional[MLEngine]:
    """Safely get ML engine component"""
    return component_manager.get_component('ml_engine')

def get_waf_rule_generator() -> Optional[WAFRuleGenerator]:
    """Safely get WAF rule generator component"""
    return component_manager.get_component('waf_rule_generator')

def get_nginx_manager() -> Optional[NginxManager]:
    """Safely get nginx manager component"""
    return component_manager.get_component('nginx_manager')

def get_traffic_collector() -> Optional[TrafficCollector]:
    """Safely get traffic collector component"""
    return component_manager.get_component('traffic_collector')

def get_real_time_processor() -> Optional[RealTimeProcessor]:
    """Safely get real-time processor component"""
    return component_manager.get_component('real_time_processor')

def get_rule_optimizer() -> Optional[RuleOptimizer]:
    """Safely get rule optimizer component"""
    return component_manager.get_component('rule_optimizer')

def require_component(component_name: str, component):
    """Raise HTTPException if component is not available"""
    if component is None:
        raise HTTPException(
            status_code=503, 
            detail=f"{component_name} not available. Check system status."
        )


# Response models
class ThreatResponse(BaseModel):
    threats: List[Dict[str, Any]]
    total_threats: int
    threat_patterns: Dict[str, int]


class SystemStatusResponse(BaseModel):
    status: str
    components: Dict[str, bool]
    timestamp: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


async def startup_components():
    """Initialize system components with comprehensive error handling"""
    logger.info("Starting component initialization...")
    
    try:
        with component_lock:
            # Initialize ML engine with error handling
            try:
                logger.info("Initializing ML engine...")
                ml_engine = MLEngine()
                component_manager.set_component('ml_engine', ml_engine)
                
                # Try to load existing model
                model_path = config.ml_model_path
                if os.path.exists(model_path):
                    try:
                        ml_engine.load_models(model_path)
                        logger.info(f"Loaded existing ML model from {model_path}")
                    except Exception as e:
                        logger.warning(f"Failed to load existing model: {e}, will use default model")
                
            except Exception as e:
                logger.error(f"Failed to initialize ML engine: {e}")
                component_manager.set_error('ml_engine', str(e))
                # Don't raise here, continue with other components
            
            # Initialize WAF rule generator with error handling
            try:
                logger.info("Initializing WAF rule generator...")
                # Use configuration values for limits
                waf_rule_generator = WAFRuleGenerator(
                    max_rules=config.waf_max_rules,
                    default_expiry_minutes=config.waf_default_expiry_minutes
                )
                component_manager.set_component('waf_rule_generator', waf_rule_generator)
                logger.info(f"WAF rule generator initialized with max_rules={config.waf_max_rules}, "
                           f"expiry={config.waf_default_expiry_minutes}min")
                
            except Exception as e:
                logger.error(f"Failed to initialize WAF rule generator: {e}")
                component_manager.set_error('waf_rule_generator', str(e))
            
            # Initialize rule optimizer with error handling
            try:
                logger.info("Initializing rule optimizer...")
                rule_optimizer = RuleOptimizer()
                component_manager.set_component('rule_optimizer', rule_optimizer)
                
            except Exception as e:
                logger.error(f"Failed to initialize rule optimizer: {e}")
                component_manager.set_error('rule_optimizer', str(e))
            
            # Initialize nginx manager with error handling
            try:
                logger.info("Initializing nginx manager...")
                # Load nginx nodes from config
                nginx_nodes = []
                nginx_nodes_env = os.getenv('NGINX_NODES', '')
                
                if nginx_nodes_env:
                    node_urls = [url.strip() for url in nginx_nodes_env.split(',') if url.strip()]
                    logger.info(f"Found nginx nodes: {node_urls}")
                    
                    # Create nginx node objects from configuration
                    for i, url in enumerate(node_urls):
                        nginx_nodes.append(NginxNode(
                            node_id=f"node_{i+1}",
                            hostname=url,
                            ssh_host=url.split('//')[1].split(':')[0],  # Extract hostname from URL
                            ssh_port=22,
                            ssh_username="nginx",
                            ssh_key_path=None,
                            nginx_config_path="/etc/nginx/conf.d",
                            nginx_reload_command="sudo systemctl reload nginx"
                        ))
                
                # 0A.13 - OVERLAY SSH CREDENTIALS ONTO THE NODES.
                #
                # NGINX_NODES points at the LOG servers (http://log-server-N:8080),
                # and this code derives ssh_host from that URL's hostname - which is
                # the log-server container, NOT the nginx node. The real node host,
                # port, username, key and reload command therefore cannot come from
                # NGINX_NODES. They come from WAF_SSH_NODES (JSON), one object per
                # node, matched by node_id. Without this, the SSH transport has
                # nothing to connect to (measured: sshd is ABSENT on the stock node
                # image, and even with sshd it would dial the log-server).
                #
                # The overlay mutates the NginxNode dataclass in place. Only the
                # fields present in the JSON entry are changed; everything else keeps
                # its value from the NGINX_NODES construction above.
                ssh_overlay = os.getenv('WAF_SSH_NODES', '')
                if ssh_overlay:
                    try:
                        overlay = json.loads(ssh_overlay)
                        by_id = {n.node_id: n for n in nginx_nodes}
                        for entry in overlay:
                            nid = entry.get('node_id')
                            if nid not in by_id:
                                logger.warning(
                                    f"WAF_SSH_NODES names node {nid!r}, which is "
                                    f"not in this cluster ({sorted(by_id)}); ignored"
                                )
                                continue
                            node = by_id[nid]
                            node.ssh_host = entry.get('ssh_host', node.ssh_host)
                            node.ssh_port = int(entry.get('ssh_port', node.ssh_port))
                            node.ssh_username = entry.get('ssh_username', node.ssh_username)
                            node.ssh_key_path = entry.get('ssh_key_path', node.ssh_key_path)
                            node.nginx_config_path = entry.get('nginx_config_path', node.nginx_config_path)
                            node.nginx_reload_command = entry.get('nginx_reload_command', node.nginx_reload_command)
                            logger.info(
                                f"SSH overlay applied to {nid}: {node.ssh_username}@"
                                f"{node.ssh_host}:{node.ssh_port}"
                            )
                    except Exception as e:
                        logger.error(f"Failed to parse WAF_SSH_NODES: {e}")
                
                if nginx_nodes:
                    nginx_manager = NginxManager(nginx_nodes)
                    component_manager.set_component('nginx_manager', nginx_manager)
                else:
                    logger.warning("No nginx nodes configured")
                
            except Exception as e:
                logger.error(f"Failed to initialize nginx manager: {e}")
                component_manager.set_error('nginx_manager', str(e))
            
            # Initialize traffic collector with error handling
            try:
                logger.info("Initializing traffic collector...")
                nginx_nodes_env = os.getenv('NGINX_NODES', '')
                
                if nginx_nodes_env:
                    node_urls = [url.strip() for url in nginx_nodes_env.split(',') if url.strip()]
                    if node_urls:
                        traffic_collector = TrafficCollector(node_urls)
                        component_manager.set_component('traffic_collector', traffic_collector)
                        
                        # Start collection in background with error handling
                        try:
                            asyncio.create_task(traffic_collector.start_collection())
                            logger.info(f"Traffic collection started for nodes: {node_urls}")
                        except Exception as e:
                            logger.error(f"Failed to start traffic collection: {e}")
                            component_manager.set_error('traffic_collector', str(e))
                else:
                    logger.warning("No NGINX_NODES environment variable found")
                    
            except Exception as e:
                logger.error(f"Failed to initialize traffic collector: {e}")
                component_manager.set_error('traffic_collector', str(e))
            
            # Initialize real-time processor if ML engine is available
            try:
                ml_engine = component_manager.get_component('ml_engine')
                if ml_engine:
                    logger.info("Initializing real-time processor...")
                    real_time_processor = RealTimeProcessor(
                        ml_engine, config.threat_threshold, config.confidence_threshold
                    )
                    component_manager.set_component('real_time_processor', real_time_processor)
                else:
                    logger.warning("ML engine not available, skipping real-time processor")
                    
            except Exception as e:
                logger.error(f"Failed to initialize real-time processor: {e}")
                component_manager.set_error('real_time_processor', str(e))
            
            logger.info("Component initialization completed")
            
            # Log component status
            status = component_manager.get_status()
            for component, details in status.items():
                if details['status'] == 'running':
                    logger.info(f"✓ {component}: running")
                elif details['status'] == 'error':
                    logger.warning(f"✗ {component}: error - {details['last_error']}")
                else:
                    logger.info(f"- {component}: {details['status']}")
            
            # Register fallback strategies for critical components
            logger.info("Registering fallback strategies...")
            degradation_manager.register_feature_dependency('traffic_analysis', ['ml_engine'])
            degradation_manager.register_feature_dependency('config_deployment', ['nginx_manager'])
            degradation_manager.register_feature_dependency('real_time_monitoring', ['traffic_collector'])
            logger.info("Fallback strategies registered successfully")
    
    except Exception as e:
        logger.error(f"Critical error during component initialization: {e}")
        raise


async def shutdown_components():
    """Shutdown system components gracefully with comprehensive error handling"""
    logger.info("Starting graceful component shutdown...")
    
    try:
        with component_lock:
            # Stop processing first
            with state_lock:
                system_state['is_processing'] = False
            
            # Shutdown traffic collector
            try:
                traffic_collector = component_manager.get_component('traffic_collector')
                if traffic_collector:
                    await traffic_collector.stop_collection()
                    logger.info("Traffic collector stopped")
            except Exception as e:
                logger.error(f"Error stopping traffic collector: {e}")
            
            # Shutdown nginx manager
            try:
                nginx_manager = component_manager.get_component('nginx_manager')
                if nginx_manager:
                    nginx_manager.cleanup_resources()
                    logger.info("Nginx manager cleaned up")
            except Exception as e:
                logger.error(f"Error cleaning up nginx manager: {e}")
            
            # Save ML model if available
            try:
                ml_engine = component_manager.get_component('ml_engine')
                if ml_engine and ml_engine.is_trained:
                    model_path = config.ml_model_path
                    os.makedirs(os.path.dirname(model_path), exist_ok=True)
                    ml_engine.save_models(model_path)
                    logger.info(f"ML model saved to {model_path}")
            except Exception as e:
                logger.error(f"Error saving ML model: {e}")
            
            # Shutdown all components
            component_manager.shutdown_all()
            logger.info("All components shutdown completed")
            
    except Exception as e:
        logger.error(f"Error during component shutdown: {e}")
    
    # Wait a moment for background tasks to finish
    await asyncio.sleep(2)


# ============= AUTHENTICATION ENDPOINTS (TEMPORARILY DISABLED) =============

# Authentication endpoints disabled for development speed
# Will be re-enabled later

@app.post("/auth/login", response_model=AuthResponse)
@rate_limit("5/minute")
async def login(request: Request, login_request: LoginRequest):
    """Authenticate user and return JWT token (5 attempts/min per client IP)"""
    try:
        user = auth_manager.authenticate_user(login_request.username, login_request.password)
        if not user:
            metrics.auth_attempts.labels(status="failed").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        metrics.auth_attempts.labels(status="success").inc()
        token = auth_manager.create_jwt_token(user.username)
        
        return AuthResponse(
            access_token=token,
            token_type="bearer",
            expires_in=config.security.jwt_expiry_hours * 3600
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        metrics.auth_attempts.labels(status="error").inc()
        raise HTTPException(status_code=500, detail="Authentication error")


# @app.post("/auth/api-key")
async def generate_api_key(
    request: ApiKeyRequest
):
    """Generate API key for user (admin only)"""
    try:
        api_key = auth_manager.generate_api_key(request.username)
        return {
            "api_key": api_key,
            "username": request.username,
            "created_at": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"API key generation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate API key")


@app.post("/auth/users", dependencies=[require_admin()])
async def create_user(
    request: UserManagementRequest
):
    """Create new user (admin only)"""
    try:
        user = auth_manager.create_user(
            username=request.username,
            password=request.password,
            roles=request.roles
        )
        return {
            "message": f"User {request.username} created successfully",
            "username": user.username,
            "roles": user.roles,
            "created_at": user.created_at.isoformat()
        }
    except Exception as e:
        logger.error(f"User creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")


@app.get("/auth/users", dependencies=[require_admin()])
async def list_users(request: Request):
    """List all users (admin only)"""
    try:
        return auth_manager.get_user_stats()
    except Exception as e:
        logger.error(f"User listing error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")


# ============= SECURITY MANAGEMENT ENDPOINTS =============

@app.get("/api/security/stats", dependencies=[require_admin()])
async def get_security_stats():
    """Get security statistics and events (admin only)"""
    try:
        # Get security middleware stats
        security_middleware = None
        for middleware in app.user_middleware:
            if isinstance(middleware.cls, type) and issubclass(middleware.cls, SecurityMiddleware):
                # This is a bit hacky, but we need to access the middleware instance
                # In a real implementation, you'd store a reference to the middleware
                break
        
        base_stats = {
            "timestamp": datetime.now().isoformat(),
            "auth_stats": auth_manager.get_user_stats(),
            "system_security": {
                "https_enabled": config.security.use_https,
                "rate_limiting": RATE_LIMITING_AVAILABLE,
                "security_headers": config.security.enable_security_headers,
                "debug_mode": config.api_debug
            }
        }
        
        return base_stats
    
    except Exception as e:
        logger.error(f"Failed to get security stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get security stats")


@app.post("/api/security/unblock-ip", dependencies=[require_admin()])
async def unblock_ip(
    ip_address: str = Query(..., description="IP address to unblock")
):
    """Unblock an IP address (admin only)"""
    try:
        # Validate IP address format
        ipaddress.ip_address(ip_address)
        
        # In a real implementation, you'd access the security middleware instance
        logger.info(f"IP unblock request for {ip_address}")
        
        return {
            "message": f"IP {ip_address} unblock requested",
            "timestamp": datetime.now().isoformat(),
            "admin": "system"
        }
    
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    except Exception as e:
        logger.error(f"Failed to unblock IP: {e}")
        raise HTTPException(status_code=500, detail="Failed to unblock IP")


@app.post("/api/security/emergency-shutdown", dependencies=[require_admin()])
async def emergency_shutdown():
    """Emergency shutdown endpoint (admin only)"""
    try:
        logger.critical(f"EMERGENCY SHUTDOWN initiated")
        
        # Stop all background processing using proper state management
        with state_lock:
            system_state['is_processing'] = False
            system_state['shutdown_requested'] = True
        
        # Could add additional emergency procedures here
        
        return {
            "message": "Emergency shutdown initiated",
            "timestamp": datetime.now().isoformat(),
            "admin": "system"
        }
    
    except Exception as e:
        logger.error(f"Emergency shutdown failed: {e}")
        raise HTTPException(status_code=500, detail="Emergency shutdown failed")


# ============= PUBLIC ENDPOINTS =============
# (0A.6: the dev-only /test-no-auth probe and the /api/debug/ routes were
# closed — see ROUTE-POLICY-0A6.txt. The panel consumes /api/panel-status.)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Nginx WAF AI System",
        "version": "0.1.0",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "security": "enabled" if not config.api_debug else "debug_mode"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Get components safely
        ml_engine = component_manager.get_component('ml_engine')
        traffic_collector = component_manager.get_component('traffic_collector')
        waf_rule_generator = component_manager.get_component('waf_rule_generator')
        nginx_manager = component_manager.get_component('nginx_manager')
        
        with component_lock:
            return {
                "status": "healthy",
                "components": {
                    "ml_engine": ml_engine is not None and getattr(ml_engine, 'is_trained', False),
                    "traffic_collector": traffic_collector is not None,
                    "waf_generator": waf_rule_generator is not None,
                    "nginx_manager": nginx_manager is not None,
                    "authentication": True,
                    "rate_limiting": RATE_LIMITING_AVAILABLE
                },
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {"status": "unhealthy", "error": str(e)}

@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint - public for monitoring"""
    try:
        # Update gauge metrics using component manager
        nginx_manager = component_manager.get_component('nginx_manager')
        waf_rule_generator = component_manager.get_component('waf_rule_generator')
        traffic_collector = component_manager.get_component('traffic_collector')
        ml_engine = component_manager.get_component('ml_engine')
        
        # Update nodes count with real values
        metrics.nodes_registered.set(len(nginx_manager.nodes) if nginx_manager and hasattr(nginx_manager, 'nodes') else 0)
        
        # Update rules count with real values
        if waf_rule_generator and hasattr(waf_rule_generator, 'active_rules'):
            metrics.rules_active.set(len(waf_rule_generator.active_rules))
        else:
            metrics.rules_active.set(0)
            
        # Update traffic metrics with real data
        if traffic_collector and hasattr(traffic_collector, 'collected_requests'):
            metrics.traffic_volume.set(len(traffic_collector.collected_requests))
        else:
            metrics.traffic_volume.set(0)
        
        if traffic_collector:
            try:
                metrics.recent_requests.set(len(traffic_collector.get_recent_requests(100)))
            except Exception:
                metrics.recent_requests.set(0)
        else:
            metrics.recent_requests.set(0)
            
    except Exception as e:
        logger.error(f"Error updating metrics: {e}")
    
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ============= PROTECTED ENDPOINTS =============

@app.get("/api/panel-status", dependencies=[require_viewer()])
async def panel_status():
    """Aggregated runtime status for the control panel (replaces /api/debug/status)"""
    
    # Get components safely using component manager
    traffic_collector = component_manager.get_component('traffic_collector')
    ml_engine = component_manager.get_component('ml_engine')
    real_time_processor = component_manager.get_component('real_time_processor')
    
    # Get processing state safely
    with state_lock:
        is_processing = system_state['is_processing']
    
    status = {
        "traffic_collector": {
            "initialized": traffic_collector is not None,
            "is_collecting": getattr(traffic_collector, 'is_collecting', False),
            "collected_requests_count": len(getattr(traffic_collector, 'collected_requests', [])),
            "recent_requests_count": len(traffic_collector.get_recent_requests(100)) if traffic_collector else 0
        },
        "ml_engine": {
            "initialized": ml_engine is not None,
            "is_trained": getattr(ml_engine, 'is_trained', False)
        },
        "real_time_processor": {
            "initialized": real_time_processor is not None
        },
        "processing": {
            "is_processing": is_processing
        },
        "components_status": component_manager.get_status()
    }
    
    return status


@app.get("/api/status", dependencies=[require_viewer()])
async def get_system_status():
    """Get system status - requires authentication"""
    # Get components safely
    traffic_collector = component_manager.get_component('traffic_collector')
    ml_engine = component_manager.get_component('ml_engine')
    real_time_processor = component_manager.get_component('real_time_processor')
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    nginx_manager = component_manager.get_component('nginx_manager')
    
    # Get processing state safely
    with state_lock:
        is_processing = system_state['is_processing']
    
    return {
        "is_processing": is_processing,
        "traffic_collector": traffic_collector is not None,
        "traffic_collector_collecting": traffic_collector.is_collecting if traffic_collector else False,
        "ml_engine": ml_engine is not None,
        "ml_engine_trained": ml_engine.is_trained if ml_engine else False,
        "real_time_processor": real_time_processor is not None,
        "waf_rule_generator": waf_rule_generator is not None,
        "nginx_manager": nginx_manager is not None,
        "recent_requests_count": len(traffic_collector.collected_requests) if traffic_collector else 0,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/health", dependencies=[require_viewer()])
async def get_system_health():
    """Get comprehensive system health including error recovery status"""
    try:
        # Get component status
        component_status = component_manager.get_status()
        
        # Get degradation status
        degradation_status = degradation_manager.get_degradation_status()
        
        # Get circuit breaker status
        circuit_breaker_status = error_recovery.get_health_status()
        
        # Get processing state
        with state_lock:
            processing_state = system_state.copy()
        
        # Calculate overall health score
        total_components = len(component_status)
        healthy_components = sum(1 for status in component_status.values() if status.get('status') == 'running')
        health_score = (healthy_components / total_components) * 100 if total_components > 0 else 0
        
        # Determine system status
        if health_score >= 90:
            system_status = "healthy"
        elif health_score >= 70:
            system_status = "degraded"
        elif health_score >= 50:
            system_status = "critical"
        else:
            system_status = "failing"
        
        return {
            "system_status": system_status,
            "health_score": round(health_score, 2),
            "processing_state": processing_state,
            "components": component_status,
            "degradation": degradation_status,
            "circuit_breakers": circuit_breaker_status,
            "error_recovery": {
                "fallbacks_available": len(error_recovery.fallback_strategies),
                "features_degraded": len(degradation_status.get('degraded_features', [])),
                "recovery_enabled": True
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to get system health: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")


@app.post("/api/nodes/add", dependencies=[require_admin()])
async def add_nginx_node(
    node: SecureNginxNodeModel
):
    """Add a new nginx node to the cluster - requires admin role"""
    global nginx_manager
    
    try:
        nginx_node = NginxNode(
            node_id=node.node_id,
            hostname=node.hostname,
            ssh_host=node.ssh_host,
            ssh_port=node.ssh_port,
            ssh_username=node.ssh_username,
            ssh_key_path=node.ssh_key_path,
            nginx_config_path=node.nginx_config_path,
            nginx_reload_command=node.nginx_reload_command,
            api_endpoint=node.api_endpoint
        )
        
        nginx_manager = component_manager.get_component('nginx_manager')
        if nginx_manager is None:
            nginx_manager = NginxManager([nginx_node])
            component_manager.set_component('nginx_manager', nginx_manager)
        else:
            nginx_manager.add_node(nginx_node)
        
        logger.info(f"Node {node.node_id} added successfully")
        return {"message": f"Node {node.node_id} added successfully"}
    
    except Exception as e:
        logger.error(f"Failed to add node {node.node_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to add node")


@app.get("/api/nodes", dependencies=[require_viewer()])
async def list_nginx_nodes():
    """List all nginx nodes - viewer role or higher required"""
    nginx_manager = component_manager.get_component('nginx_manager')
    if nginx_manager is None:
        return {"nodes": []}
    
    return {
        "nodes": [node.to_dict() for node in nginx_manager.nodes.values()],
        "total_nodes": len(nginx_manager.nodes)
    }


@app.get("/api/nodes/status", dependencies=[require_viewer()])
async def get_cluster_status():
    """Get status of all nginx nodes - requires authentication"""
    nginx_manager = component_manager.get_component('nginx_manager')
    if nginx_manager is None:
        raise HTTPException(status_code=404, detail="No nginx manager configured")
    
    try:
        status = await nginx_manager.get_cluster_status()
        return status
    except Exception as e:
        logger.error(f"Failed to get cluster status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get cluster status")


@app.post("/api/training/start", dependencies=[require_operator()])
async def start_training():
    """Start ML model training - operator role or higher required"""
    ml_engine = component_manager.get_component('ml_engine')
    if ml_engine is None:
        raise HTTPException(status_code=500, detail="ML engine not initialized")
    
    try:
        logger.info("Training started via API")
        
        # Get real training data from traffic collector if available
        traffic_collector = component_manager.get_component('traffic_collector')
        training_data = []
        labels = []
        
        if traffic_collector and hasattr(traffic_collector, 'collected_requests') and len(traffic_collector.collected_requests) >= 50:
            # Use real collected traffic data
            logger.info("Using real traffic data for training")
            for request in traffic_collector.collected_requests:
                training_data.append(request.to_dict())
                # Simple heuristic labeling based on patterns
                if request._check_sql_patterns():
                    labels.append("sql_injection")
                elif request._check_xss_patterns():
                    labels.append("xss_attack")
                else:
                    labels.append("normal")
        else:
            # Generate synthetic training data
            logger.info("Generating synthetic training data")
            generator = TrainingDataGenerator()
            training_data, labels = generator.generate_training_data(
                num_samples=1000,
                threat_ratio=0.3
            )
        
        if len(training_data) < 10:
            raise HTTPException(status_code=400, detail=f"Insufficient training data. Need at least 10 samples, got {len(training_data)}")
        
        ml_engine.train_models(training_data, labels)
        
        # ML-3: the exposed accuracy is the HELD-OUT evaluation accuracy
        # computed by the engine during training. No held-out evaluation
        # (small dataset, single-class split, no labels) -> no accuracy
        # number is invented; the metric is left untouched.
        evaluation = getattr(ml_engine, "last_evaluation", None)
        model_accuracy = evaluation["accuracy"] if evaluation else None
        if model_accuracy is not None:
            metrics.ml_model_accuracy.set(model_accuracy)
        
        logger.info(f"Training completed successfully with {len(training_data)} samples")
        return {
            "message": "Training completed successfully",
            "is_trained": ml_engine.is_trained,
            "training_samples": len(training_data),
            "model_accuracy": model_accuracy,
            "evaluation": evaluation,
            "data_source": "real_traffic" if traffic_collector and len(traffic_collector.collected_requests) >= 50 else "synthetic",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise HTTPException(status_code=500, detail="Training failed")


@app.post("/api/traffic/start-collection", dependencies=[require_operator()])
async def start_traffic_collection(
    node_urls: List[str]
):
    """Start collecting traffic from nginx nodes - requires operator role"""
    
    try:
        # Validate URLs
        if not node_urls:
            raise HTTPException(status_code=400, detail="At least one node URL required")
        
        for url in node_urls:
            if not url.startswith(('http://', 'https://')):
                raise HTTPException(status_code=400, detail=f"Invalid URL format: {url}")
        
        traffic_collector = TrafficCollector(node_urls)
        component_manager.set_component('traffic_collector', traffic_collector)
        
        # Start collection in background
        asyncio.create_task(traffic_collector.start_collection())
        
        logger.info(f"Traffic collection started for nodes: {node_urls}")
        return {
            "message": "Traffic collection started",
            "nodes": node_urls,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to start traffic collection: {e}")
        raise HTTPException(status_code=500, detail="Failed to start traffic collection")


@app.get("/api/traffic/stats", dependencies=[require_viewer()])
async def get_traffic_stats():
    """Get traffic collection statistics - viewer role or higher required"""
    traffic_collector = component_manager.get_component('traffic_collector')
    if traffic_collector is None:
        return {"message": "Traffic collection not started", "total_requests": 0}
    
    try:
        recent_requests = traffic_collector.get_recent_requests(100)
        
        return {
            "total_requests": len(traffic_collector.collected_requests),
            "recent_requests": len(recent_requests),
            "is_collecting": traffic_collector.is_collecting,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to get traffic stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get traffic stats")


@app.post("/api/processing/start", dependencies=[require_operator()])
async def start_real_time_processing():
    """Start real-time processing of traffic"""
    logger.info("API ENDPOINT: Starting real-time processing...")
    
    # Use proper synchronization for state management
    with state_lock:
        if system_state['is_processing']:
            raise HTTPException(status_code=400, detail="Real-time processing is already running")
        
        # Check component availability with proper locking
        ml_engine = component_manager.get_component('ml_engine')
        traffic_collector = component_manager.get_component('traffic_collector')
        
        if ml_engine is None or not ml_engine.is_trained:
            logger.error("API ENDPOINT: ML engine is not trained!")
            raise HTTPException(status_code=400, detail="ML engine must be trained first")
        
        if traffic_collector is None:
            logger.error("API ENDPOINT: Traffic collector is not initialized!")
            raise HTTPException(status_code=400, detail="Traffic collector must be initialized first")
        
        # Initialize real-time processor if needed
        real_time_processor = component_manager.get_component('real_time_processor')
        if real_time_processor is None:
            try:
                real_time_processor = RealTimeProcessor(ml_engine)
                component_manager.set_component('real_time_processor', real_time_processor)
                logger.info("API ENDPOINT: Created new RealTimeProcessor")
            except Exception as e:
                logger.error(f"Failed to create RealTimeProcessor: {e}")
                raise HTTPException(status_code=500, detail="Failed to initialize real-time processor")
        
        # Set processing flag with proper synchronization
        system_state['is_processing'] = True
        logger.info("API ENDPOINT: Real-time processing flag set to True")
    
    # Start background tasks with error handling
    try:
        logger.info("API ENDPOINT: Creating traffic processing task...")
        task1 = asyncio.create_task(process_traffic_continuously())
        logger.info("API ENDPOINT: Creating threat processing task...")
        task2 = asyncio.create_task(process_threats_continuously())
        logger.info("API ENDPOINT: Both tasks created successfully!")
        
        # Store tasks for potential cleanup
        system_state['background_tasks'] = [task1, task2]
        
    except Exception as e:
        # Rollback processing state if task creation fails
        with state_lock:
            system_state['is_processing'] = False
        logger.error(f"Failed to start background tasks: {e}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to start background processing")
    
    return {
        "message": "Real-time processing started",
        "timestamp": datetime.now().isoformat()
    }


async def process_traffic_continuously():
    """Continuously process traffic from the traffic collector"""
    logger.info("Starting continuous traffic processing...")
    
    # Get current processing state with proper synchronization
    def is_processing_active():
        with state_lock:
            return system_state['is_processing']
    
    while is_processing_active():
        try:
            # Get components safely
            traffic_collector = component_manager.get_component('traffic_collector')
            real_time_processor = component_manager.get_component('real_time_processor')
            
            if traffic_collector and real_time_processor and hasattr(traffic_collector, 'collected_requests'):
                logger.debug(f"Traffic collector has {len(traffic_collector.collected_requests)} collected requests")
                
                # Get recent requests and process a copy to avoid race conditions
                requests_to_process = traffic_collector.get_recent_requests(100)
                logger.debug(f"Found {len(requests_to_process)} requests to process")
                
                if requests_to_process:
                    # Process on a copy and remove processed requests afterward
                    processed_count = 0
                    
                    for request in requests_to_process:
                        try:
                            # Check if we should continue processing
                            if not is_processing_active():
                                logger.info("Processing stopped during request processing")
                                break
                                
                            # Use node_id from the request
                            node_id = request.node_id
                            logger.debug(f"Processing request with node_id: {node_id} from {request.url}")
                            
                            # Measure processing time
                            start_time = asyncio.get_event_loop().time()
                            
                            # Process the request with ML engine
                            request_dict = request.to_dict()
                            predictions = await real_time_processor.process_requests([request_dict])
                            prediction = predictions[0] if predictions else None
                            
                            # Record processing time
                            processing_time = asyncio.get_event_loop().time() - start_time
                            metrics.processing_time.labels(component='ml_engine').observe(processing_time)
                            
                            # Extract status code (simulate based on URL)
                            status = '200'
                            if 'admin' in request.url or 'backup' in request.url:
                                status = '403'
                            elif 'nonexistent' in request.url:
                                status = '404'
                            elif prediction and is_threat(prediction, config.threat_threshold, config.confidence_threshold):
                                status = '403'  # Block threats
                            
                            # Increment metrics
                            print(f"Incrementing metrics: node_id={node_id}, status={status}")
                            metrics.requests_total.labels(node_id=node_id, status=status).inc()
                            
                            # Check for threats with updated threshold
                            if prediction and is_threat(prediction, config.threat_threshold, config.confidence_threshold):
                                threat_type = prediction.threat_type
                                if threat_type == 'normal':
                                    # Override with pattern-based detection
                                    if request._check_sql_patterns():
                                        threat_type = 'sql_injection'
                                        metrics.sql_injection_attempts.labels(node_id=node_id).inc()
                                    elif request._check_xss_patterns():
                                        threat_type = 'xss_attack'
                                        metrics.xss_attempts.labels(node_id=node_id).inc()
                                    elif '/etc/' in request.url or '/.env' in request.url or '../' in request.url:
                                        threat_type = 'path_traversal'
                                        metrics.path_traversal_attempts.labels(node_id=node_id).inc()
                                    elif any(scanner in request.headers.get('User-Agent', '').lower() for scanner in ['nmap', 'masscan', 'zap', 'burp', 'sqlmap']):
                                        threat_type = 'scanner_activity'
                                        metrics.scanner_attempts.labels(node_id=node_id).inc()
                                    elif 'admin' in request.url or 'backup' in request.url or 'config' in request.url:
                                        threat_type = 'unauthorized_access'
                                else:
                                    # Increment specific metrics based on threat type
                                    if threat_type == 'sql_injection':
                                        metrics.sql_injection_attempts.labels(node_id=node_id).inc()
                                    elif threat_type == 'xss_attack':
                                        metrics.xss_attempts.labels(node_id=node_id).inc()
                                    elif threat_type == 'path_traversal':
                                        metrics.path_traversal_attempts.labels(node_id=node_id).inc()
                                    elif threat_type == 'scanner_activity':
                                        metrics.scanner_attempts.labels(node_id=node_id).inc()
                                
                                # If request was blocked, increment blocked requests metric
                                if status == '403':
                                    metrics.blocked_requests.labels(node_id=node_id, reason=threat_type).inc()
                                
                                metrics.threats_detected.labels(threat_type=threat_type).inc()
                                print(f"Threat detected: {threat_type} (score: {prediction.threat_score:.3f}, confidence: {prediction.confidence:.3f})")
                            
                            processed_count += 1
                            
                        except Exception as e:
                            logger.error(f"Error processing individual request: {e}")
                            traceback.print_exc()
                    
                    # Clear processed requests to avoid reprocessing
                    if processed_count > 0:
                        traffic_collector.collected_requests = traffic_collector.collected_requests[processed_count:]
                else:
                    print("No requests to process, continuing...")
            else:
                print("Traffic collector not available")
                
        except Exception as e:
            print(f"Error in processing cycle: {e}")
            traceback.print_exc()
        
        # Update active rules count
        waf_rule_generator = component_manager.get_component('waf_rule_generator')
        if waf_rule_generator:
            metrics.rules_active.set(len(getattr(waf_rule_generator, 'active_rules', [])))
        
        await asyncio.sleep(2)  # Process every 2 seconds


async def process_threats_continuously():
    """Continuously process threats and generate rules"""
    logger.info("THREAT PROCESSOR: Starting threat processing loop!")
    
    # Get current processing state with proper synchronization
    def is_processing_active():
        with state_lock:
            return system_state['is_processing']
    
    while is_processing_active():
        try:
            # Get components safely
            traffic_collector = component_manager.get_component('traffic_collector')
            real_time_processor = component_manager.get_component('real_time_processor')
            waf_rule_generator = component_manager.get_component('waf_rule_generator')
            
            logger.debug(f"THREAT PROCESSOR: Components check - traffic_collector: {traffic_collector is not None}, real_time_processor: {real_time_processor is not None}, waf_rule_generator: {waf_rule_generator is not None}")
            
            if traffic_collector and real_time_processor and waf_rule_generator:
                # Get recent requests
                recent_requests = traffic_collector.get_recent_requests(100)
                logger.info(f"THREAT PROCESSOR: Threat processor found {len(recent_requests)} recent requests")
                
                if recent_requests:
                    # Check if we should continue processing
                    if not is_processing_active():
                        logger.info("THREAT PROCESSOR: Processing stopped during threat analysis")
                        break
                    
                    # Convert to dict format for ML processing
                    request_dicts = [req.to_dict() for req in recent_requests]
                    
                    # Detect threats
                    logger.info(f"THREAT PROCESSOR: Processing {len(request_dicts)} requests for threat detection...")
                    process_start_time = asyncio.get_event_loop().time()
                    threats = await real_time_processor.process_requests(request_dicts)
                    process_time = asyncio.get_event_loop().time() - process_start_time
                    
                    logger.info(f"THREAT PROCESSOR: Detected {len(threats)} threats")
                    
                    # Update metrics
                    for threat in threats:
                        threat_type = threat.to_dict().get('threat_type', 'unknown')
                        metrics.threats_detected.labels(threat_type=threat_type).inc()
                    
                    metrics.processing_time.labels(component='threat_detection').observe(process_time)
                    
                    if threats:
                        # Generate WAF rules
                        threat_patterns = real_time_processor.get_threat_patterns()
                        threat_dicts = [threat.to_dict() for threat in threats]
                        
                        logger.info(f"THREAT PROCESSOR: Generating rules from {len(threat_dicts)} threats...")
                        
                        # Measure rule generation time
                        rule_generation_start = asyncio.get_event_loop().time()
                        
                        new_rules = waf_rule_generator.generate_rules_from_threats(
                            threat_dicts, threat_patterns
                        )
                        
                        # Record rule generation time
                        rule_generation_time = asyncio.get_event_loop().time() - rule_generation_start
                        metrics.rule_generation_duration.observe(rule_generation_time)
                        
                        logger.info(f"THREAT PROCESSOR: Generated {len(new_rules)} new WAF rules in {rule_generation_time:.3f}s")
                        
                        # Get nginx manager for deployment
                        nginx_manager = component_manager.get_component('nginx_manager')
                        if new_rules and nginx_manager:
                            # Deploy rules to nginx nodes
                            logger.info(f"THREAT PROCESSOR: Deploying {len(new_rules)} rules to nginx nodes...")
                            nginx_config = waf_rule_generator.generate_nginx_config(new_rules)
                            deployment_results = await nginx_manager.deploy_rules_to_all_nodes(nginx_config)

                            # Consume the result. This is the AUTOMATIC path - it runs on
                            # its own with nobody watching - so an unconditional success
                            # log here is the worst place for a false signal: the system
                            # would tell itself it was protecting people when it was not.
                            # A rule that is staged but not loaded protects nothing.
                            failed_nodes = [nid for nid, ok in (deployment_results or {}).items() if not ok]
                            if failed_nodes:
                                logger.error(
                                    f"THREAT PROCESSOR: Rules NOT active on {failed_nodes} "
                                    f"(staged but not loaded); {len(new_rules)} rules are not protecting traffic"
                                )
                            elif deployment_results:
                                logger.info(
                                    f"THREAT PROCESSOR: Rules deployed and active on "
                                    f"{list(deployment_results.keys())}"
                                )
                            else:
                                logger.warning(
                                    "THREAT PROCESSOR: Deployment returned no node results"
                                )
                    else:
                        logger.debug("THREAT PROCESSOR: No threats detected in this cycle")
                else:
                    logger.debug("THREAT PROCESSOR: No recent requests for threat processing")
            else:
                missing = []
                if not traffic_collector: missing.append("traffic_collector")
                if not real_time_processor: missing.append("real_time_processor") 
                if not waf_rule_generator: missing.append("waf_rule_generator")
                logger.warning(f"THREAT PROCESSOR: Threat processing skipped - missing: {missing}")
                
            # Clean up old data periodically
            # if traffic_collector:
            #     traffic_collector.clear_old_requests(60)
        
        except Exception as e:
            logger.error(f"THREAT PROCESSOR: Error in threat processing cycle: {e}")
            traceback.print_exc()
        
        await asyncio.sleep(10)  # Process every 10 seconds
    
    logger.info("THREAT PROCESSOR: Threat processing loop ended!")


@app.get("/api/threats", dependencies=[require_viewer()])
async def get_recent_threats() -> ThreatResponse:
    """Get recent threat detections - viewer role or higher required"""
    real_time_processor = component_manager.get_component('real_time_processor')
    if real_time_processor is None:
        return ThreatResponse(threats=[], total_threats=0, threat_patterns={})
    
    threats = [threat.to_dict() for threat in real_time_processor.recent_threats]
    threat_patterns = real_time_processor.get_threat_patterns()
    
    # Update threat metrics when fetching data
    try:
        # Count threats by type for metrics
        threat_counts = {}
        for threat in threats:
            threat_type = threat.get('threat_type', 'unknown')
            if threat_type != 'normal':
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        # Update Prometheus metrics
        for threat_type, count in threat_counts.items():
            # Set the counter to the current count (this is a gauge-like behavior)
            # In a real system, you'd increment counters as threats are detected
            current_value = metrics.threats_detected.labels(threat_type=threat_type)._value._value
            if current_value < count:
                metrics.threats_detected.labels(threat_type=threat_type).inc(count - current_value)
                
    except Exception as e:
        logger.warning(f"Failed to update threat metrics: {e}")
    
    return ThreatResponse(
        threats=threats,
        total_threats=len(threats),
        threat_patterns=threat_patterns
    )


@app.get("/api/rules", dependencies=[require_viewer()])
async def get_active_rules():
    """Get currently active WAF rules - viewer role or higher required"""
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        return {"rules": [], "total_rules": 0}
    
    active_rules = waf_rule_generator.get_active_rules()
    
    return {
        "rules": [rule.to_dict() for rule in active_rules],
        "total_rules": len(active_rules),
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/rules/deploy", dependencies=[require_operator()])
async def deploy_rules(
    request: SecureRuleDeploymentRequest
):
    """Deploy WAF rules to nginx nodes - operator role or higher required"""
    nginx_manager = component_manager.get_component('nginx_manager')
    if nginx_manager is None:
        raise HTTPException(status_code=404, detail="No nginx manager configured")
    
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    try:
        # Convert dict rules back to WAFRule objects if needed
        rules = waf_rule_generator.get_active_rules()
        
        rule_optimizer = component_manager.get_component('rule_optimizer')
        if rule_optimizer:
            try:
                rules = rule_optimizer.optimize_rules(rules)
                logger.info("Rules optimized successfully")
            except Exception as e:
                logger.warning(f"Rule optimization failed: {e}, proceeding with original rules")
        
        # Generate nginx configuration with validation
        try:
            nginx_config = waf_rule_generator.generate_nginx_config(rules)

            # Validate nginx configuration before deployment.
            #
            # TWO DEFECTS CORRECTED HERE, both found by an independent review of the
            # deployment path (2026-10-16):
            #
            # 1. THE GUARD COULD NOT FAIL, AND FAILED OPEN. It read:
            #        if hasattr(nginx_manager, '_validate_nginx_config'):
            #            if not nginx_manager._validate_nginx_config(nginx_config):
            #                raise HTTPException(400, ...)
            #    `hasattr` is ALWAYS True for a method defined on the class, so the
            #    condition was dead - and in the impossible False case, validation
            #    would have been SKIPPED and the deployment would have proceeded
            #    unvalidated. A guard whose failure mode is "do the dangerous thing"
            #    is worse than no guard, because it reads like protection.
            #    Calling the method directly is the honest form: if it is ever
            #    removed, this raises AttributeError loudly instead of quietly
            #    deploying unvalidated rules.
            #
            # 2. AN INVALID CONFIG WAS REPORTED AS A SERVER ERROR. The 400 raised
            #    here was caught by the `except Exception` below and re-raised as
            #    500 "Configuration generation failed", so an operator saw "our
            #    server broke" when the truth was "the rules you asked for are
            #    invalid". HTTPException is now passed through untouched, so the
            #    400 reaches the caller with its real meaning.
            if not nginx_manager._validate_nginx_config(nginx_config):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Generated nginx configuration is invalid and was NOT "
                        "deployed. The rules were rejected before reaching any "
                        "node."
                    ),
                )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to generate nginx configuration: {e}")
            raise HTTPException(status_code=500, detail="Configuration generation failed")
        
        # Deploy to specified nodes or all nodes with comprehensive error handling
        try:
            # SELECTIVE DEPLOYMENT, AND WHY THE OLD FORM WAS A LIE.
            #
            # This used to be:
            #     if request.node_ids:
            #         deployment_results = await ...deploy_rules_to_all_nodes(nginx_config)
            #     else:
            #         deployment_results = await ...deploy_rules_to_all_nodes(nginx_config)
            # Both branches called the SAME function on ALL nodes. The API accepted
            # and validated `node_ids`, then ignored it - so a caller asking to deploy
            # to one node had every node changed, with no error and no warning. In a
            # multi-tenant product "deploy to this tenant's node" is a safety
            # boundary, not a convenience: silently widening the target set is how a
            # rule meant for one tenant reaches another's traffic.
            #
            # The parameter is now honoured, and an unknown node id is REFUSED rather
            # than silently dropped - a typo in a node id must not look like success.
            # EMPTY LIST IS NOT "NOT GIVEN" - and treating it as such changes every node.
            #
            # This read `if request.node_ids:`. In Python an empty list is FALSY, so a
            # caller sending node_ids=[] - "target nothing", or a defensively empty
            # list - fell through to the else branch and had rules deployed to EVERY
            # node, with a success report. Found by an independent review of b47fac7,
            # 2026-10-16, and reproduced:
            #     bool([])        -> False   -> all-nodes branch
            #     bool(['node_1']) -> True   -> selective branch
            # The validator in src/validation.py does NOT catch it either: it iterates
            # the list to check each id's format, so an empty list has nothing to check
            # and passes through.
            #
            # The distinction the code needs is "was the parameter SUPPLIED", not
            # "is it truthy". `is not None` says that. An explicitly empty list is then
            # refused rather than silently widened: a request to deploy to no node is
            # either a mistake or a deliberate no-op, and neither should touch a fleet.
            if request.node_ids is not None:
                if not request.node_ids:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "node_ids was supplied but empty. This would target no "
                            "node, so it is refused rather than silently widened to "
                            "every node. Omit node_ids entirely to target all nodes."
                        ),
                    )
                deployment_results = await nginx_manager.deploy_rules_to_specific_nodes(
                    request.node_ids, nginx_config
                )
            else:
                deployment_results = await nginx_manager.deploy_rules_to_all_nodes(nginx_config)
            
            # Update deployment metrics
            for node_id, success in deployment_results.items():
                if success:
                    metrics.rules_deployed.labels(node_id=node_id).inc(len(rules))
                    metrics.configuration_reloads.labels(node_id=node_id, status='success').inc()
                else:
                    metrics.configuration_reloads.labels(node_id=node_id, status='failed').inc()
            
            # Check deployment results.
            #
            # This used to raise only when EVERY node failed, and then log
            # "Rules deployed successfully" unconditionally. A PARTIAL failure -
            # one node enforcing, one not - was therefore reported as success, and
            # an operator reading "deployed" would believe the rule was in force
            # everywhere. In a security product that is the worst kind of wrong.
            #
            # A deployment is only successful if EVERY node it targeted confirms
            # the rules are active. Anything less is reported as a failure, with
            # the per-node results preserved so the operator can see which nodes
            # are protecting traffic and which are not.
            failed_deployments = [
                node_id for node_id, success in deployment_results.items() if not success
            ]

            # NOTHING DEPLOYED IS NOT SUCCESS - the vacuous-truth hole.
            #
            # Found by an independent review of b47fac7, 2026-10-16, and reproduced:
            # with an empty node set, deploy_rules_to_all_nodes() returns {}, so
            # `failed_deployments` is [] and the check below does not fire. The endpoint
            # then returns 200 "Rules deployed and confirmed active on all nodes" over
            # ZERO nodes - the strongest possible claim about the weakest possible set.
            #
            # This is unreachable in the current compose config (the manager is built
            # with at least one node, and an empty node_ids list is now refused above),
            # so it is NOT live. It is fixed anyway because "unreachable" is not
            # "absent": remove a node at runtime, or build the manager differently, and
            # this silently becomes the most dishonest response the API can give. A
            # previous review found this exact shape once, which is why it is fixed
            # rather than noted.
            if not deployment_results:
                logger.error(
                    "Deployment targeted NO nodes: nothing was attempted. This is not "
                    "a success."
                )
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "No node was targeted, so nothing was deployed. This is not a "
                        "success: rules are protecting no traffic."
                    ),
                )

            if failed_deployments:
                active_nodes = [
                    node_id for node_id, success in deployment_results.items() if success
                ]
                logger.error(
                    f"Deployment NOT fully active. Failed nodes: {failed_deployments}; "
                    f"active nodes: {active_nodes or 'none'}. "
                    f"{len(rules)} rule(s) are NOT protecting traffic on "
                    f"{len(failed_deployments)} node(s)."
                )
                raise HTTPException(
                    status_code=500,
                    detail={
                        "message": (
                            "Deployment did not become active on every node. "
                            "Rules are staged but NOT ACTIVE on the failed nodes, "
                            "so they are not protecting traffic there."
                        ),
                        "failed_nodes": failed_deployments,
                        "active_nodes": active_nodes,
                        "deployment_results": deployment_results,
                    },
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Deployment error: {e}")
            # Update failed deployment metrics
            if 'deployment_results' in locals():
                for node_id in deployment_results.keys():
                    metrics.configuration_reloads.labels(node_id=node_id, status='failed').inc()
            raise HTTPException(status_code=500, detail="Deployment failed")

        # Reached only when EVERY targeted node confirmed the rules are active.
        logger.info(
            f"Rules deployed and confirmed ACTIVE on all nodes: "
            f"{list(deployment_results.keys())}"
        )
        return {
            "message": "Rules deployed and confirmed active on all nodes",
            "deployment_results": deployment_results,
            "total_rules": len(rules),
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during rule deployment: {e}")
        raise HTTPException(status_code=500, detail="Deployment error")


@app.get("/api/config/nginx", dependencies=[require_operator()])
async def get_nginx_config():
    """Generate and return nginx configuration - requires operator role"""
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    try:
        active_rules = waf_rule_generator.get_active_rules()
        nginx_config = waf_rule_generator.generate_nginx_config(active_rules)
        
        return {
            "config": nginx_config,
            "total_rules": len(active_rules),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to generate nginx config: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate nginx config")
        raise HTTPException(status_code=500, detail="Failed to generate nginx config")


@app.get("/api/rules/stats", dependencies=[require_viewer()])
async def get_rule_stats():
    """Get WAF rule generation and management statistics"""
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    try:
        stats = waf_rule_generator.get_rule_stats()
        active_rules = waf_rule_generator.get_active_rules()
        
        # Add detailed breakdown
        rule_types = {}
        for rule in active_rules:
            rule_types[rule.rule_type] = rule_types.get(rule.rule_type, 0) + 1
        
        return {
            "rule_statistics": stats,
            "rule_types_breakdown": rule_types,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get rule stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get rule stats")


@app.post("/api/rules/cleanup", dependencies=[require_operator()])
async def cleanup_rules():
    """Manually trigger rule cleanup (remove expired rules)"""
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    try:
        expired_count = waf_rule_generator.cleanup_expired_rules()
        enforced_count = waf_rule_generator.enforce_rule_limits()
        
        return {
            "message": "Rule cleanup completed",
            "expired_rules_removed": expired_count,
            "oldest_rules_removed": enforced_count,
            "active_rules_remaining": len(waf_rule_generator.active_rules),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to cleanup rules")


@app.post("/api/rules/configure", dependencies=[require_operator()])
async def configure_rule_limits(
    max_rules: Optional[int] = None,
    default_expiry_minutes: Optional[int] = None
):
    """Configure rule limits and expiry times"""
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    # Validate parameters
    if max_rules is not None and (max_rules < 1 or max_rules > 1000):
        raise HTTPException(status_code=400, detail="max_rules must be between 1 and 1000")
    
    if default_expiry_minutes is not None and (default_expiry_minutes < 1 or default_expiry_minutes > 1440):
        raise HTTPException(status_code=400, detail="default_expiry_minutes must be between 1 and 1440 (24 hours)")
    
    try:
        waf_rule_generator.configure_limits(max_rules, default_expiry_minutes)
        
        return {
            "message": "Rule configuration updated",
            "max_rules": waf_rule_generator.max_rules,
            "default_expiry_minutes": waf_rule_generator.default_expiry_minutes,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to configure rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to configure rules")


@app.delete("/api/rules/expire", dependencies=[require_operator()])
async def expire_rules(
    rule_ids: Optional[List[str]] = None,
    rule_types: Optional[List[str]] = None
):
    """Manually expire specific rules by ID or type"""
    if not rule_ids and not rule_types:
        raise HTTPException(status_code=400, detail="Must specify either rule_ids or rule_types")
    
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    try:
        removed_count = waf_rule_generator.manually_expire_rules(rule_ids, rule_types)
        
        return {
            "message": "Rules expired successfully",
            "removed_count": removed_count,
            "active_rules_remaining": len(waf_rule_generator.active_rules),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to expire rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to expire rules")


@app.post("/api/processing/stop", dependencies=[require_operator()])
async def stop_processing():
    """Stop real-time processing - requires operator role"""
    try:
        with state_lock:
            if not system_state['is_processing']:
                raise HTTPException(status_code=400, detail="Real-time processing is not currently running")
            
            system_state['is_processing'] = False
            logger.info("Real-time processing stopped via API")
        
        # Allow some time for background tasks to gracefully stop
        await asyncio.sleep(1)
        
        return {
            "message": "Real-time processing stopped",
            "timestamp": datetime.now().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to stop processing: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop processing")


@app.get("/api/stats", dependencies=[require_viewer()])
async def get_system_stats():
    """Get overall system statistics - viewer role or higher required"""
    try:
        # Get components safely
        ml_engine = component_manager.get_component('ml_engine')
        traffic_collector = component_manager.get_component('traffic_collector')
        real_time_processor = component_manager.get_component('real_time_processor')
        waf_rule_generator = component_manager.get_component('waf_rule_generator')
        nginx_manager = component_manager.get_component('nginx_manager')
        
        # Get processing state safely
        with state_lock:
            is_processing = system_state['is_processing']
        
        stats = {
            "timestamp": datetime.now().isoformat(),
            "components": {
                "ml_engine_trained": ml_engine is not None and ml_engine.is_trained,
                "traffic_collection_active": traffic_collector is not None and traffic_collector.is_collecting,
                "real_time_processing": is_processing,
                "nginx_nodes_count": len(nginx_manager.nodes) if nginx_manager else 0
            },
            "traffic": {
                "total_requests": len(traffic_collector.collected_requests) if traffic_collector else 0,
                "recent_requests": len(traffic_collector.get_recent_requests(100)) if traffic_collector else 0
            },
            "threats": {
                "total_threats": len(real_time_processor.recent_threats) if real_time_processor else 0
            },
            "rules": {
                "active_rules": len(waf_rule_generator.get_active_rules()) if waf_rule_generator else 0
            }
        }
        
        return stats
    
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system stats")





# ============= TLS/HTTPS CONFIGURATION =============

def create_ssl_context():
    """Create SSL context for HTTPS"""
    if not config.security.use_https:
        return None
    
    try:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(
            config.security.ssl_cert_path,
            config.security.ssl_key_path
        )
        ssl_context.check_hostname = False
        ssl_context.verify_mode = config.security.ssl_verify_mode
        
        logger.info("SSL context created successfully")
        return ssl_context
    
    except Exception as e:
        logger.error(f"Failed to create SSL context: {e}")
        raise


# ============= SERVER STARTUP =============

if __name__ == "__main__":
    # Create SSL context if HTTPS is enabled
    ssl_context = create_ssl_context()
    
    # Configure uvicorn
    uvicorn_config = {
        "host": config.api_host,
        "port": config.api_port,
        "log_level": config.log_level.lower(),
        "access_log": True,
        "server_header": False,  # Security: don't reveal server info
        "date_header": False     # Security: don't reveal server time
    }
    
    if ssl_context:
        uvicorn_config["ssl_context"] = ssl_context
        logger.info(f"Starting HTTPS server on {config.api_host}:{config.api_port}")
    else:
        logger.info(f"Starting HTTP server on {config.api_host}:{config.api_port}")
    
    if config.api_debug:
        logger.warning("Debug mode enabled - disable in production!")
        uvicorn_config["reload"] = True
    
    # Start the server
    uvicorn.run(app, **uvicorn_config)
