"""
Module Loader for Aetheris Vault Dashboard.

Registration works by explicitly listing module names in REGISTERED_MODULES.
Each module must have a manifest.py declaring its metadata and routes.
The loader validates, mounts, and reports all registered route surfaces.
"""

import os
import importlib
from flask import abort, g
from app.routes.auth import get_current_user

# ── REGISTER YOUR MODULES HERE ───────────────────────────────────────
# Add module folder names to activate them. Order determines priority.
REGISTERED_MODULES = [
    "home",
    "drive",
    "graph",
    "admin",
]
# ─────────────────────────────────────────────────────────────────────

_modules_dir = os.path.join(os.path.dirname(__file__), 'modules')
_loaded_modules = {}   # name → manifest dict


class ModuleManifest:
    """Base class every module manifest must implement."""
    name: str = ""
    description: str = ""
    admin_only: bool = False # Secure flag for privilege isolation
    routes: list[str] = []   # declared route patterns, e.g. ["/home", "/home/<path:sub>"]

    def get_view(self, module_name: str, **kwargs):
        """Called by the router to render a route. Must return a Flask response."""
        raise NotImplementedError


def load_modules(blueprint):
    """
    Load and register all modules listed in REGISTERED_MODULES.
    Called once by the dashboard blueprint on startup.
    Returns a report of loaded modules and their routes.
    """
    report = []

    for mod_name in REGISTERED_MODULES:
        mod_path = os.path.join(_modules_dir, mod_name)
        manifest_path = os.path.join(mod_path, 'manifest.py')

        # Validate module folder and manifest exist
        if not os.path.isdir(mod_path):
            print(f"[LOADER] ✗ Module '{mod_name}' — folder not found, skipping")
            continue
        if not os.path.isfile(manifest_path):
            print(f"[LOADER] ✗ Module '{mod_name}' — missing manifest.py, skipping")
            continue

        # Dynamically import the manifest module
        try:
            spec_path = f"app.dash.modules.{mod_name}.manifest"
            manifest_mod = importlib.import_module(spec_path)
            manifest: ModuleManifest = manifest_mod.Manifest()
        except Exception as e:
            print(f"[LOADER] ✗ Module '{mod_name}' — manifest import error: {e}")
            continue

        # Validate required fields
        if not manifest.name or not manifest.routes:
            print(f"[LOADER] ✗ Module '{mod_name}' — manifest missing name/routes")
            continue

        # Register each declared route into the blueprint
        for route_pattern in manifest.routes:
            full_route = f"/{mod_name}{route_pattern if route_pattern != '/' else ''}"
            _register_route(blueprint, full_route, mod_name, manifest)

        _loaded_modules[mod_name] = manifest
        mounted_routes = [f"/app/{mod_name}{r if r != '/' else ''}" for r in manifest.routes]
        report.append({
            "module": manifest.name,
            "folder": mod_name,
            "routes": mounted_routes,
            "description": manifest.description,
        })
        print(f"[LOADER] ✓ Module '{manifest.name}' mounted → {mounted_routes}")

    return report


def _register_route(blueprint, route: str, mod_name: str, manifest: ModuleManifest):
    """Dynamically register a single route on the blueprint."""
    # Use unique endpoint names to prevent collisions
    # Flask requires routes and endpoint names to be unique
    safe_route = route.replace('/', '_').replace('<', '').replace('>', '').replace(':', '_')
    endpoint = f"module_{mod_name}{safe_route}"

    def view_func(**kwargs):
        # 1. Global Auth is already enforced by before_request in __init__.py
        
        # 2. Administrative Audit Gate
        if manifest.admin_only and not g.user.get('is_admin'):
            abort(403) # System-level rejection for unauthorized access
            
        return manifest.get_view(mod_name, **kwargs)

    view_func.__name__ = endpoint  # Flask requires unique function names
    blueprint.add_url_rule(route, endpoint=endpoint, view_func=view_func, methods=['GET', 'POST', 'PATCH', 'DELETE'])


def get_loaded_modules():
    """Return currently loaded modules and their routes."""
    return {
        name: {
            "name": m.name,
            "description": m.description,
            "admin_only": m.admin_only,
            "routes": m.routes
        }
        for name, m in _loaded_modules.items()
    }
