# stb.py
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import RequestException, JSONDecodeError

# Logger konfigurieren (Aufrufender Code kann Level ändern)
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Session mit Retries (HTTP + HTTPS)
s = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=0.1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=frozenset(["GET"]),
)
s.mount("http://", HTTPAdapter(max_retries=retries))
s.mount("https://", HTTPAdapter(max_retries=retries))

DEFAULT_TIMEOUT = 5.0  # Sekunden

def _build_headers(token: Optional[str] = None) -> Dict[str, str]:
    headers = {"User-Agent": "Mozilla/5.0 (QtEmbedded; U; Linux; C)"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

def _build_cookies(mac: str) -> Dict[str, str]:
    # timezone und Sprache sind hartcodiert wie im Original
    return {"mac": mac, "stb_lang": "en", "timezone": "Europe/London"}

def _request_get(
    url: str, *, proxies: Optional[Dict[str, str]] = None, **kwargs
) -> Optional[requests.Response]:
    try:
        resp = s.get(url, proxies=proxies or None, timeout=DEFAULT_TIMEOUT, **kwargs)
        resp.raise_for_status()
        return resp
    except RequestException as e:
        logger.debug("HTTP GET failed for %s: %s", url, e)
        return None

def getUrl(target_url: str, proxy: Optional[str] = None) -> Optional[str]:
    """
    Versucht die xpcom.common.js / ähnliche Dateien auf dem Portal zu laden und
    extrahiert daraus die Portal-URL.
    Gibt die Portal-URL als String zurück oder None bei Fehlern.
    """
    def parse_response(requested_url: str, response: requests.Response) -> Optional[str]:
        try:
            # Minimiere Format-Noise ähnlich wie im Original, aber sicherer behandeln
            java = response.text.replace(" ", "").replace("'", "").replace("+", "")
            m_pattern = re.search(r"varpattern.*\/(\(http.*)\/;", java)
            if not m_pattern:
                logger.debug("Kein varpattern gefunden in %s", requested_url)
                return None
            pattern = m_pattern.group(1)
            result = re.search(pattern, requested_url)
            if not result:
                logger.debug("Pattern '%s' passt nicht auf '%s'", pattern, requested_url)
                return None

            def find_group_int(expr: str) -> Optional[int]:
                m = re.search(expr, java)
                if not m:
                    return None
                try:
                    return int(m.group(1))
                except (IndexError, ValueError):
                    return None

            protocolIndex = find_group_int(r"this\.portal_protocol.*(\d).*;")
            ipIndex = find_group_int(r"this\.portal_ip.*(\d).*;")
            pathIndex = find_group_int(r"this\.portal_path.*(\d).*;")
            if None in (protocolIndex, ipIndex, pathIndex):
                logger.debug("Fehlende Index-Angaben im JS (protocol/ip/path)")
                return None

            try:
                protocol = result.group(protocolIndex)
                ip = result.group(ipIndex)
                path = result.group(pathIndex)
            except IndexError:
                logger.debug("Index-Extraktion aus Regex-Ergebnis ist fehlgeschlagen")
                return None

            portal_pattern_m = re.search(r"this\.ajax_loader=(.*\.php);", java)
            if not portal_pattern_m:
                logger.debug("Kein ajax_loader pattern gefunden")
                return None
            portal_pattern = portal_pattern_m.group(1)

            portal = (
                portal_pattern.replace("this.portal_protocol", protocol)
                .replace("this.portal_ip", ip)
                .replace("this.portal_path", path)
            )
            return portal
        except Exception as e:
            logger.exception("Fehler beim Parsen der Antwort von %s: %s", requested_url, e)
            return None

    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        logger.debug("Ungültige URL: %s", target_url)
        return None
    base = f"{parsed.scheme}://{parsed.netloc}"

    candidate_paths = [
        "/c/xpcom.common.js",
        "/client/xpcom.common.js",
        "/c_/xpcom.common.js",
        "/stalker_portal/c/xpcom.common.js",
        "/stalker_portal/c_/xpcom.common.js",
    ]

    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = _build_headers()

    # Versuche mit Proxy (falls vorhanden) bzw. ohne Proxy
    for try_proxies in (proxies, None):
        for p in candidate_paths:
            url = base + p
            resp = _request_get(url, headers=headers) if try_proxies is None else _request_get(url, headers=headers, proxies=try_proxies)
            if resp:
                portal = parse_response(url, resp)
                if portal:
                    logger.info("Portal gefunden: %s", portal)
                    return portal
    logger.debug("Kein passendes xpcom.common.js gefunden für %s", target_url)
    return None

def getToken(url: str, mac: str, proxy: Optional[str] = None) -> Optional[str]:
    """
    Führt Handshake aus und gibt token zurück oder None.
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    cookies = _build_cookies(mac)
    headers = _build_headers()

    full_url = f"{url}?type=stb&action=handshake&JsHttpRequest=1-xml"
    resp = _request_get(full_url, cookies=cookies, headers=headers, proxies=proxies)
    if not resp:
        return None
    try:
        token = resp.json().get("js", {}).get("token")
        if token:
            return token
    except (ValueError, JSONDecodeError) as e:
        logger.debug("JSON-Decode-Fehler in getToken: %s", e)
    return None

def getProfile(url: str, mac: str, token: str, proxy: Optional[str] = None) -> Optional[Dict[str, Any]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    cookies = _build_cookies(mac)
    headers = _build_headers(token)

    full_url = f"{url}?type=stb&action=get_profile&JsHttpRequest=1-xml"
    resp = _request_get(full_url, cookies=cookies, headers=headers, proxies=proxies)
    if not resp:
        return None
    try:
        profile = resp.json().get("js")
        return profile
    except (ValueError, JSONDecodeError) as e:
        logger.debug("JSON-Decode-Fehler in getProfile: %s", e)
        return None

def getExpires(url: str, mac: str, token: str, proxy: Optional[str] = None) -> Optional[Any]:
    """
    Liefert (wie im Original) den Wert response.json()['js']['phone'] zurück -- das Feld
    'expires' war im Original nicht vorhanden; prüfen ob dies korrekt ist.
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    cookies = _build_cookies(mac)
    headers = _build_headers(token)

    full_url = f"{url}?type=account_info&action=get_main_info&JsHttpRequest=1-xml"
    resp = _request_get(full_url, cookies=cookies, headers=headers, proxies=proxies)
    if not resp:
        return None
    try:
        return resp.json().get("js", {}).get("phone")
    except (ValueError, JSONDecodeError) as e:
        logger.debug("JSON-Decode-Fehler in getExpires: %s", e)
        return None

def getAllChannels(url: str, mac: str, token: str, proxy: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    cookies = _build_cookies(mac)
    headers = _build_headers(token)

    full_url = f"{url}?type=itv&action=get_all_channels&force_ch_link_check=&JsHttpRequest=1-xml"
    resp = _request_get(full_url, cookies=cookies, headers=headers, proxies=proxies)
    if not resp:
        return None
    try:
        return resp.json().get("js", {}).get("data")
    except (ValueError, JSONDecodeError) as e:
        logger.debug("JSON-Decode-Fehler in getAllChannels: %s", e)
        return None

def getGenres(url: str, mac: str, token: str, proxy: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    cookies = _build_cookies(mac)
    headers = _build_headers(token)

    full_url = f"{url}?action=get_genres&type=itv&JsHttpRequest=1-xml"
    resp = _request_get(full_url, cookies=cookies, headers=headers, proxies=proxies)
    if not resp:
        return None
    try:
        return resp.json().get("js")
    except (ValueError, JSONDecodeError) as e:
        logger.debug("JSON-Decode-Fehler in getGenres: %s", e)
        return None

def getGenreNames(url: str, mac: str, token: str, proxy: Optional[str] = None) -> Optional[Dict[str, str]]:
    genre_data = getGenres(url, mac, token, proxy)
    if not genre_data:
        return None
    genres: Dict[str, str] = {}
    try:
        for i in genre_data:
            gid = i.get("id")
            name = i.get("title")
            if gid is None or name is None:
                continue
            genres[str(gid)] = name
        return genres if genres else None
    except Exception as e:
        logger.debug("Fehler beim Aufbau von Genre-Namen: %s", e)
        return None

def getLink(url: str, mac: str, token: str, cmd: str, proxy: Optional[str] = None) -> Optional[str]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    cookies = _build_cookies(mac)
    headers = _build_headers(token)

    full_url = (
        f"{url}?type=itv&action=create_link&cmd={cmd}"
        "&series=0&forced_storage=false&disable_ad=false&download=false&force_ch_link_check=false&JsHttpRequest=1-xml"
    )
    resp = _request_get(full_url, cookies=cookies, headers=headers, proxies=proxies)
    if not resp:
        return None
    try:
        data = resp.json()
        # Original: data["js"]["cmd"].split()[-1]
        cmd_field = data.get("js", {}).get("cmd")
        if not cmd_field:
            return None
        link = cmd_field.split()[-1]
        return link
    except (ValueError, JSONDecodeError, AttributeError, IndexError) as e:
        logger.debug("Fehler beim Parsen des Links: %s", e)
        return None

def getEpg(url: str, mac: str, token: str, period: int, proxy: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    cookies = _build_cookies(mac)
    headers = _build_headers(token)

    full_url = f"{url}?type=itv&action=get_epg_info&period={period}&JsHttpRequest=1-xml"
    resp = _request_get(full_url, cookies=cookies, headers=headers, proxies=proxies)
    if not resp:
        return None
    try:
        return resp.json().get("js", {}).get("data")
    except (ValueError, JSONDecodeError) as e:
        logger.debug("JSON-Decode-Fehler in getEpg: %s", e)
        return None
