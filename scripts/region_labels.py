"""Conservative display labels for proxy nodes.

Country is inferred only from explicit country tokens/flags in the source name.
Unknown or ambiguous names are never geo-guessed; they receive 🌐.
"""
from __future__ import annotations

import re

COUNTRIES = {
    "DE": ("🇩🇪", ("germany", "deutschland", "frankfurt", "berlin")),
    "NL": ("🇳🇱", ("netherlands", "holland", "amsterdam")),
    "FR": ("🇫🇷", ("france", "paris")),
    "GB": ("🇬🇧", ("united kingdom", "britain", "england", "london", "uk")),
    "US": ("🇺🇸", ("united states", "usa", "america", "new york", "los angeles", "us")),
    "CA": ("🇨🇦", ("canada", "toronto", "montreal")),
    "TR": ("🇹🇷", ("turkey", "turkiye", "istanbul", "ankara")),
    "AE": ("🇦🇪", ("uae", "united arab emirates", "dubai")),
    "FI": ("🇫🇮", ("finland", "helsinki")),
    "SE": ("🇸🇪", ("sweden", "stockholm")),
    "NO": ("🇳🇴", ("norway", "oslo")),
    "CH": ("🇨🇭", ("switzerland", "zurich")),
    "AT": ("🇦🇹", ("austria", "vienna")),
    "PL": ("🇵🇱", ("poland", "warsaw")),
    "CZ": ("🇨🇿", ("czech", "prague")),
    "ES": ("🇪🇸", ("spain", "madrid")),
    "IT": ("🇮🇹", ("italy", "milan", "rome")),
    "RU": ("🇷🇺", ("russia", "moscow", "st petersburg")),
    "CN": ("🇨🇳", ("china", "hong kong", "shanghai", "beijing")),
    "JP": ("🇯🇵", ("japan", "tokyo")),
    "KR": ("🇰🇷", ("south korea", "korea", "seoul")),
    "SG": ("🇸🇬", ("singapore",)),
    "IN": ("🇮🇳", ("india", "mumbai", "delhi")),
    "IR": ("🇮🇷", ("iran", "tehran")),
    "BR": ("🇧🇷", ("brazil", "sao paulo")),
    "AU": ("🇦🇺", ("australia", "sydney")),
}

REGION_BY_COUNTRY = {
    **{c: "اروپا" for c in ("DE","NL","FR","GB","FI","SE","NO","CH","AT","PL","CZ","ES","IT")},
    **{c: "آسیا" for c in ("TR","AE","RU","CN","JP","KR","SG","IN","IR")},
    **{c: "آمریکا" for c in ("US","CA","BR")},
    "AU": "اقیانوسیه",
}

def identify_country(name: str) -> tuple[str, str, str]:
    """Return (country code, flag, region); unknown names stay explicitly unknown."""
    value = (name or "").strip()
    for code, (flag, aliases) in COUNTRIES.items():
        if flag in value:
            return code, flag, REGION_BY_COUNTRY.get(code, "سایر")
        padded = f" {re.sub(r'[^a-z0-9]+', ' ', value.lower()).strip()} "
        if re.search(rf"(?<![a-z0-9]){re.escape(code.lower())}(?![a-z0-9])", padded):
            return code, flag, REGION_BY_COUNTRY.get(code, "سایر")
        if any(alias in padded for alias in aliases):
            return code, flag, REGION_BY_COUNTRY.get(code, "سایر")
    return "ZZ", "🌐", "سایر"

def display_name(original: str) -> tuple[str, str]:
    """Return a short flag+region name and region label."""
    _code, flag, region = identify_country(original)
    return f"{flag} · {region}", region
