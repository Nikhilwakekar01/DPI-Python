"""Application classification matching the active C++ sniToAppType chain."""

from __future__ import annotations

from .models import AppType


def classify_domain(sni: str) -> AppType:
    """Map a supplied SNI/domain using the C++ ordered substring checks."""
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    if (
        "google" in lower_sni
        or "gstatic" in lower_sni
        or "googleapis" in lower_sni
        or "ggpht" in lower_sni
        or "gvt1" in lower_sni
    ):
        return AppType.GOOGLE

    if (
        "youtube" in lower_sni
        or "ytimg" in lower_sni
        or "youtu.be" in lower_sni
        or "yt3.ggpht" in lower_sni
    ):
        return AppType.YOUTUBE

    if (
        "facebook" in lower_sni
        or "fbcdn" in lower_sni
        or "fb.com" in lower_sni
        or "fbsbx" in lower_sni
        or "meta.com" in lower_sni
    ):
        return AppType.FACEBOOK

    if "instagram" in lower_sni or "cdninstagram" in lower_sni:
        return AppType.INSTAGRAM

    if "whatsapp" in lower_sni or "wa.me" in lower_sni:
        return AppType.WHATSAPP

    if (
        "twitter" in lower_sni
        or "twimg" in lower_sni
        or "x.com" in lower_sni
        or "t.co" in lower_sni
    ):
        return AppType.TWITTER

    if (
        "netflix" in lower_sni
        or "nflxvideo" in lower_sni
        or "nflximg" in lower_sni
    ):
        return AppType.NETFLIX

    if (
        "amazon" in lower_sni
        or "amazonaws" in lower_sni
        or "cloudfront" in lower_sni
        or "aws" in lower_sni
    ):
        return AppType.AMAZON

    if (
        "microsoft" in lower_sni
        or "msn.com" in lower_sni
        or "office" in lower_sni
        or "azure" in lower_sni
        or "live.com" in lower_sni
        or "outlook" in lower_sni
        or "bing" in lower_sni
    ):
        return AppType.MICROSOFT

    if (
        "apple" in lower_sni
        or "icloud" in lower_sni
        or "mzstatic" in lower_sni
        or "itunes" in lower_sni
    ):
        return AppType.APPLE

    if "telegram" in lower_sni or "t.me" in lower_sni:
        return AppType.TELEGRAM

    if (
        "tiktok" in lower_sni
        or "tiktokcdn" in lower_sni
        or "musical.ly" in lower_sni
        or "bytedance" in lower_sni
    ):
        return AppType.TIKTOK

    if "spotify" in lower_sni or "scdn.co" in lower_sni:
        return AppType.SPOTIFY

    if "zoom" in lower_sni:
        return AppType.ZOOM

    if "discord" in lower_sni or "discordapp" in lower_sni:
        return AppType.DISCORD

    if "github" in lower_sni or "githubusercontent" in lower_sni:
        return AppType.GITHUB

    if "cloudflare" in lower_sni or "cf-" in lower_sni:
        return AppType.CLOUDFLARE

    return AppType.HTTPS


sni_to_app_type = classify_domain


__all__ = ["classify_domain", "sni_to_app_type"]
