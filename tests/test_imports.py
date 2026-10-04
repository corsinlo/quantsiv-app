import importlib
import pkgutil

import app


def test_every_module_imports():
    for mod in pkgutil.walk_packages(app.__path__, "app."):
        importlib.import_module(mod.name)
