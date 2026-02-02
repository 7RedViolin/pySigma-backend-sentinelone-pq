from .sentinelone_pq import SentinelOnePQBackend
from importlib.metadata import version, PackageNotFoundError

backends = {
    "sentinelone_pq": SentinelOnePQBackend
}

try:
    __version__ = version("pySigma-backend-sentinelone-pq")
except PackageNotFoundError:
    # package is not installed
    __version__ = "0.0.0"