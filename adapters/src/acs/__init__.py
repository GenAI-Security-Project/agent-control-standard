"""ACS reference adapters: the Python client side of the Agent Control Standard."""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("acs-adapters")
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = ["__version__"]
