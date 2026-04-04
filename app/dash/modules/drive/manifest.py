import os
from flask import render_template, g
from app.dash.loader import ModuleManifest

class Manifest(ModuleManifest):
    name        = "Drive"
    description = "Encrypted Hierarchical File Manager."
    routes      = ["/", "/<path:sub>"]

    def get_view(self, module_name: str, **kwargs):
        # The base HTML for the drive UI.
        # Data will primarily be loaded asynchronously via the Drive API.
        return render_template(
            f"modules/{module_name}/index.html",
            user=g.user,
            module_name=module_name,
        )
