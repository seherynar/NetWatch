# NetWatch - Ağ Tarama ve Risk Analiz Paneli

NetWatch yerel ağdaki cihazları ve açık portları analiz etmek için geliştirilmiş web tabanlı bir güvenlik izleme panelidir.

Bu projede amaç yalnızca Nmap çıktısını göstermek değil; açık portları risk seviyelerine göre değerlendirmek, önceki taramalarla karşılaştırmak ve ağ üzerindeki değişiklikleri daha anlaşılır hale getirmektir.

## Proje Özeti

Kullanıcı panel üzerinden hedef IP adresi veya subnet bilgisi girerek ağ taraması başlatır. Sistem Nmap ile tarama yapar, bulunan açık portları listeler ve bu portları risk seviyelerine göre analiz eder.

Ayrıca sistem önceki taramalarla karşılaştırma yaparak yeni açılan portları tespit edebilir. Böylece ağda beklenmeyen değişiklikler daha kolay fark edilir.

## Özellikler

- Web tabanlı yönetim paneli
- Hedef IP veya subnet tarama
- Nmap ile açık port tespiti
- Servis bilgisi görüntüleme
- Port bazlı risk analizi
- Düşük, orta ve yüksek risk sınıflandırması
- Önceki taramalarla karşılaştırma
- Yeni açık port tespiti
- Alarm kayıtları
- Tarama geçmişi
- Basit kullanıcı girişi
- Türkçe arayüz

## Kullanılan Teknolojiler

- Python
- Flask
- SQLite
- Nmap
- HTML
- CSS
- Bootstrap

## Proje Yapısı

```text
NetSentinel/
│
├── app.py
├── database.py
├── scanner_core.py
├── risk_engine.py
├── requirements.txt
├── README.md
│
├── data/
├── reports/
├── static/
│   └── style.css
│
└── templates/
    ├── login.html
    ├── dashboard.html
    ├── scan_results.html
    └── alerts.html
```

## Kurulum

Projeyi çalıştırmak için önce sanal ortam oluşturun:

```bash
python3 -m venv venv
```

Sanal ortamı aktif edin:

```bash
source venv/bin/activate
```

Gerekli paketleri yükleyin:

```bash
pip install -r requirements.txt
```

Projeyi başlatın:

```bash
python app.py
```

Tarayıcıdan şu adrese gidin:

```text
http://127.0.0.1:5000
```

## Kullanım

Panel açıldıktan sonra kullanıcı giriş yapar ve dashboard ekranına ulaşır.

Dashboard üzerinden hedef IP adresi veya subnet bilgisi girilerek tarama başlatılır.

Örnek hedefler:

```text
127.0.0.1
192.168.1.1
192.168.1.0/24
```

Tarama sonucunda bulunan açık portlar, servis bilgileri ve risk seviyeleri ekranda gösterilir.

## Risk Analizi Mantığı

Sistem bulunan açık portları belirli kurallara göre değerlendirir.

Örneğin:

- SSH, FTP, Telnet gibi servisler dikkat edilmesi gereken servislerdir.
- Telnet gibi güvensiz servisler daha yüksek riskli kabul edilir.
- Bilinen cihazda yeni bir port açılmışsa sistem bunu alarm olarak kaydeder.

Risk seviyeleri genel olarak şu şekilde ayrılır:

- Düşük risk
- Orta risk
- Yüksek risk

## Alarm Sistemi

NetSentinel, önceki taramalara göre ağda yeni bir açık port tespit ederse bunu alarm olarak kaydeder.

Örnek alarm:

```text
Bilinen cihazda yeni açık port tespit edildi: 127.0.0.1:8000/tcp - http
```

Bu sayede sistem yalnızca anlık tarama sonucu göstermez, ağdaki değişiklikleri de takip eder.

## Veritabanı

Projede SQLite kullanılmıştır. Tarama sonuçları, cihaz bilgileri ve alarm kayıtları veritabanında saklanır.

Bu yapı sayesinde geçmiş taramalar incelenebilir ve yeni taramalarla karşılaştırma yapılabilir.

## Geliştirme Notları

Bu proje, ağ güvenliği, açık port analizi ve temel güvenlik izleme süreçlerini daha iyi anlamak için geliştirilmiştir.

Projede Nmap çıktısı doğrudan gösterilmek yerine, sonuçlar yorumlanarak daha okunabilir bir panele dönüştürülmüştür. Böylece hem ağ tarama hem de risk değerlendirme mantığı bir arada uygulanmıştır.

İlerleyen aşamalarda projeye kullanıcı rolleri, gelişmiş raporlama, PDF rapor alma ve daha detaylı zafiyet eşleştirme özellikleri eklenebilir.