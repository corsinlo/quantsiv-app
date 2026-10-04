class ScanError(Exception):
    """A scan failure whose message is safe to store and show to users (A15).

    Anything else that goes wrong is stored as "Internal error" and logged.
    """
