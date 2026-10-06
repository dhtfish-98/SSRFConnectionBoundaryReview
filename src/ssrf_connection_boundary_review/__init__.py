"""Bounded, local-first SSRF connection boundary laboratory."""

from .core import (
    AddressPolicy,
    DirectConnector,
    FetchBlocked,
    FetchResult,
    Fetcher,
    LabOnlyPolicy,
    PublicOnlyPolicy,
    ResolvedTarget,
)

__version__ = "0.1.0"
__author__ = "dhtfish98"

__all__ = [
    "AddressPolicy",
    "DirectConnector",
    "FetchBlocked",
    "FetchResult",
    "Fetcher",
    "LabOnlyPolicy",
    "PublicOnlyPolicy",
    "ResolvedTarget",
]
