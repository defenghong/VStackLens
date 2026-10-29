"""Read X.509 validity in memory. This never verifies a chain or exports PEM."""
import base64
import hashlib
import re
from datetime import datetime, timezone


def certificate_dates(pem):
    if not isinstance(pem, str) or len(pem) > 2 * 1024 * 1024:
        raise ValueError("certificate missing or oversized")
    match = re.search(r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----", pem)
    if not match:
        raise ValueError("certificate format")
    der = base64.b64decode(re.sub(r"\s", "", match.group(1)), validate=True)

    def tlv(data, offset=0):
        if offset + 2 > len(data):
            raise ValueError("truncated DER")
        tag, size = data[offset], data[offset + 1]
        start = offset + 2
        if size & 0x80:
            width = size & 0x7f
            if not 1 <= width <= 4 or start + width > len(data):
                raise ValueError("DER length")
            size = int.from_bytes(data[start:start + width], "big")
            start += width
        end = start + size
        if end > len(data):
            raise ValueError("DER length")
        return tag, data[start:end], end

    tag, certificate, _ = tlv(der)
    if tag != 0x30:
        raise ValueError("DER certificate")
    tag, body, _ = tlv(certificate)
    if tag != 0x30 or not body:
        raise ValueError("DER body")
    pos = 0
    if body[0] == 0xA0:
        _, _, pos = tlv(body, pos)
    for _ in range(3):
        _, _, pos = tlv(body, pos)
    tag, validity, _ = tlv(body, pos)
    if tag != 0x30:
        raise ValueError("DER validity")
    start_tag, start_bytes, next_pos = tlv(validity)
    end_tag, end_bytes, _ = tlv(validity, next_pos)

    def date(tag, raw):
        text = raw.decode("ascii")
        if tag == 0x17 and re.fullmatch(r"\d{12}Z", text):
            year = int(text[:2]) + (2000 if int(text[:2]) < 50 else 1900)
            return datetime.strptime(str(year) + text[2:], "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        if tag == 0x18 and re.fullmatch(r"\d{14}Z", text):
            return datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        raise ValueError("DER date")

    start, end = date(start_tag, start_bytes), date(end_tag, end_bytes)
    now = datetime.now(timezone.utc)
    return {"valid_from": start.isoformat(), "expires_at": end.isoformat(),
            "expired": end <= now, "not_yet_valid": start > now,
            "certificate_sha256": hashlib.sha256(der).hexdigest()}
