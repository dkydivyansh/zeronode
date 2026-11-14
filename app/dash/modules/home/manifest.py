import os
import time
from flask import render_template, g
from app.dash.loader import ModuleManifest
from app.modules.user_data import get_user_manager

_template_dir = os.path.dirname(__file__)


class Manifest(ModuleManifest):
    name        = "Home"
    description = "Primary dashboard home screen showing user identity and storage status."
    routes      = ["/"]   # mounts at /app/home

    def get_view(self, module_name: str, **kwargs):
        manager = get_user_manager()
        vault_stats = manager.get_vault_stats()

        return render_template(
            f"modules/{module_name}/index.html",
            user=g.user,
            module_name=module_name,
            vault_stats=vault_stats,
            now_ts=int(time.time()),
        )
