
# NetWatch

NetWatch, izinli hedefler üzerinde Nmap taramaları yaparak açık portları, servis bilgilerini ve risk seviyelerini web paneli üzerinden gösteren Flask tabanlı bir ağ izleme uygulamasıdır.

Bu proje; ağ güvenliği, port tarama, risk analizi ve geçmiş taramalarla karşılaştırma mantığını öğrenmek amacıyla geliştirilmiştir.

## Projenin Amacı

NetWatch’un amacı, küçük ölçekli ağlarda açık portları ve çalışan servisleri daha anlaşılır şekilde takip etmektir. Uygulama, yapılan taramaları kaydeder ve önceki sonuçlarla karşılaştırarak yeni açılan portlar için uyarı oluşturur.

## Temel Özellikler

* IP adresi veya subnet üzerinde Nmap taraması yapma
* Açık portları ve servisleri listeleme
* Portlara göre düşük, orta ve yüksek risk analizi yapma
* Önceki taramalarla karşılaştırma
* Yeni açık portlar için alarm kaydı oluşturma
* Tarama geçmişini görüntüleme
* Basit ve anlaşılır web arayüzü

## Kullanılan Teknolojiler

* Python
* Flask
* SQLite
* Nmap
* HTML
* CSS
* Jinja2

## Proje Yapısı

```text
NetWatch/
│
├── app.py
├── database.py
├── scanner_core.py
├── risk_engine.py
├── original_scanner.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── data/
├── reports/
├── static/
│   └── style.css
│
└── templates/
    ├── base.html
    ├── dashboard.html
    ├── history.html
    ├── scan_result.html
    └── alerts.html
```

## Kurulum ve Çalıştırma

Projeyi bilgisayarınıza klonlayın:

```bash
git clone https://github.com/seherynar/NetWatch.git
cd NetWatch
```

Sanal ortam oluşturun:

```bash
python -m venv venv
```

Sanal ortamı aktif edin:

```bash
venv\Scripts\activate
```

Gerekli Python paketlerini yükleyin:

```bash
pip install -r requirements.txt
```

Nmap’in bilgisayarınızda kurulu olup olmadığını kontrol edin:

```bash
nmap --version
```

Eğer Nmap kurulu değilse, Windows için Nmap kurulumu yapılmalıdır. Kurulumdan sonra terminali yeniden açıp tekrar kontrol edebilirsiniz.

Uygulamayı çalıştırın:

```bash
python app.py
```

Tarayıcıdan açın:

```text
http://127.0.0.1:5000
```

## Kullanım

1. Web panelini açın.
2. Taranacak IP adresini veya subnet bilgisini girin.
3. Tarama işlemini başlatın.
4. Açık portları, servisleri ve risk seviyelerini görüntüleyin.
5. Alarm kayıtları ve tarama geçmişi üzerinden değişiklikleri takip edin.

## Risk Analizi Mantığı

NetWatch, bulunan portları temel risk seviyelerine ayırır. Örneğin bazı yönetim, uzak bağlantı veya veritabanı servisleri daha yüksek riskli olarak değerlendirilebilir. Bu analiz, temel güvenlik farkındalığı sağlamak için hazırlanmıştır.

## Güvenlik Notu

Bu proje yalnızca eğitim amacıyla ve izinli ağlarda kullanılmalıdır. Size ait olmayan sistemlerde veya izin alınmamış ağlarda tarama yapmak yasal ve etik değildir.

## Geliştirilebilecek Alanlar

* Kullanıcı giriş sistemi geliştirilebilir.
* Daha detaylı raporlama eklenebilir.
* PDF rapor çıktısı oluşturulabilir.
* Risk analizi daha kapsamlı hale getirilebilir.
* Zamanlanmış otomatik tarama sistemi eklenebilir.

## Proje Durumu

Proje temel ağ tarama, risk analizi ve alarm kayıtlarını destekleyen çalışır bir prototip olarak hazırlanmıştır.
