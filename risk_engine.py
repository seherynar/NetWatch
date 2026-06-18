"""NetWatch için risk değerlendirme yardımcıları.

Bu modül, bulunan açık portlara göre basit ve açıklanabilir bir risk seviyesi üretir.
Tam kapsamlı bir CVSS hesaplaması değildir; eğitim ve port farkındalığı amacıyla hazırlanmıştır.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskResult:
    level: str
    score: int
    reason: str


CRITICAL_PORTS = {
    23: "Telnet şifrelenmemiş bir servistir ve internete açık bırakılmamalıdır.",
    445: "SMB servisi açık olduğunda yatay hareket ve dosya paylaşımı riskleri oluşabilir.",
    5900: "VNC servisi uzak masaüstü erişimi sağlayabilir ve dikkatli yapılandırılmalıdır.",
}


HIGH_PORTS = {
    21: "FTP hatalı yapılandırılırsa kullanıcı bilgileri veya dosyalar açığa çıkabilir.",
    3306: "MySQL veritabanı servisi herkese açık şekilde yayınlanmamalıdır.",
    5432: "PostgreSQL veritabanı servisi herkese açık şekilde yayınlanmamalıdır.",
    3389: "RDP servisi uzak erişim riski oluşturabilir.",
    6379: "Redis servisi yetkisiz veri erişimine yol açabilir.",
    9200: "Elasticsearch servisi açık bırakılırsa indekslenmiş veriler sızabilir.",
}


MEDIUM_PORTS = {
    22: "SSH erişimi sınırlandırılmalı ve güçlü kimlik doğrulama ile korunmalıdır.",
    25: "SMTP servisi hatalı yapılandırılırsa kötüye kullanılabilir.",
    53: "DNS servisi yanlış yapılandırmalara karşı izlenmelidir.",
    80: "HTTP şifrelenmemiştir; mümkünse HTTPS tercih edilmelidir.",
    110: "POP3 eski bir protokoldür ve güvenli yapılandırılmadığında risk oluşturabilir.",
    143: "IMAP servisi TLS ile güvenli hale getirilmelidir.",
    8080: "Alternatif HTTP servisi açık olduğu için yapılandırması kontrol edilmelidir.",
}


LOW_PORTS = {
    443: "HTTPS beklenen bir servistir; yine de sertifika ve yapılandırma kontrol edilmelidir.",
}


def classify_risk(port: int, service: str = "") -> RiskResult:
    """Tespit edilen açık port için basit bir risk seviyesi döndürür."""

    service_l = (service or "").lower()

    if port in CRITICAL_PORTS:
        return RiskResult("Critical", 95, CRITICAL_PORTS[port])

    if port in HIGH_PORTS:
        return RiskResult("High", 80, HIGH_PORTS[port])

    if port in MEDIUM_PORTS:
        return RiskResult("Medium", 55, MEDIUM_PORTS[port])

    if port in LOW_PORTS:
        return RiskResult("Low", 25, LOW_PORTS[port])

    if any(word in service_l for word in ["telnet", "vnc"]):
        return RiskResult(
            "Critical",
            90,
            "Uzak erişim veya şifrelenmemiş servis tespit edildi."
        )

    if any(word in service_l for word in ["mysql", "postgres", "redis", "rdp", "smb"]):
        return RiskResult(
            "High",
            75,
            "Hassas servis türü tespit edildi."
        )

    if any(word in service_l for word in ["ssh", "ftp", "http"]):
        return RiskResult(
            "Medium",
            50,
            "Yaygın kullanılan ağ servisi tespit edildi; erişim kontrol edilmelidir."
        )

    return RiskResult(
        "Info",
        10,
        "Yüksek riskli bir servis eşleşmesi bulunmadı; değişiklikler izlenmelidir."
    )