import nmap # type: ignore
from datetime import datetime
import json
import os
BASELINE_FILE = 'baseline.json'
current_scan = {}

print(f"[*] {datetime.now().strftime('%H:%M:%S')} - NetSentinel temiz kurulumla başlatıldı.")
nm = nmap.PortScanner()
target_ip = '127.0.0.1'

try:
    print("[*] Tarama motoru başlatıldı, hedefler analiz ediliyor...")
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, 'r') as f:
                baseline_data = json.load(f)
                print(f"[*] Mevcut baseline veritabanı yüklendi.")
        except json.JSONDecodeError:
            print("[-] Baseline dosyası bozuk veya geçersiz. Yeni bir baseline oluşturulacak.")
    else:
        print("[*] Baseline dosyası bulunamadı. İlk taramada oluşturulacak.")
    nm.scan(hosts=target_ip, arguments='-F')
    
    for host in nm.all_hosts():
        print(f"\n[+] Canlı Cihaz: {host} (Durum: {nm[host].state().upper()})")
        current_scan[host] = {}

        for proto in nm[host].all_protocols():
            print(f"  --- Protokol: {proto.upper()} ---")
            current_scan[host][proto] = {}
            
            for port in nm[host][proto].keys():
                servis = nm[host][proto][port]['name']
                print(f"      |__ Port: {port} | Servis: {servis}")

                current_scan[host][proto][str(port)] = servis

        
            if not baseline_data:
                with open(BASELINE_FILE, 'w') as f:
                    json.dump(current_scan, f, indent=4)
                    print(f"\n[+] İlk tarama tamamlandı ve baseline okaydedildi: {BASELINE_FILE}")
            else:
                print("\n[+]Yeni tarama verileri alındı. Karşılaştırma motoruna gönderilmeye hazır.")
                alarmlar = []
                for host in current_scan:
                    if host not in baseline_data:
                        mesaj = f"[!!!] ALARM: Yeni cihaz tespit edildi! IP: {host}"
                        print(mesaj)
                        alarmlar.append(mesaj)
                    else:
                        for proto in current_scan[host]:
                            if proto in baseline_data[host]:
                                for port in current_scan[host][proto]:
                                    if port not in baseline_data[host][proto]:
                                        yeni_servis = current_scan[host][proto][port]
                                        mesaj = f"[!!!] ALARM: Bilinen cihazda YENİ PROTOKOL tespit edildi! IP: {host} - Port: {port} - Servis: {yeni_servis}"
                                        print(mesaj)
                                        alarmlar.append(mesaj)
                                        
                            
                            else:
                                mesaj = f"[!!!] ALARM: Bilinen cihazda YENİ PROTOKOL tespit edildi! IP: {host} - Protokol: {proto.upper()}"
                                print(mesaj)
                                alarmlar.append(mesaj)
            if alarmlar:
                zaman_damgasi = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                rapor_adi = f"guvenlik_raporu_{zaman_damgasi}.txt"

                with open(rapor_adi, 'w' , encoding='utf-8') as f:
                    f.write("[NetSentinel Güvenlik Raporu]\n")
                    f.write(f"Tarih: {zaman_damgasi}\n")
                    f.write("-" * 50 + "\n")

                    for alarm in alarmlar:
                        f.write(alarm + "\n")
                    f.write("-" * 50 + "\n")
                    f.write(f"Toplam{len(alarmlar)} adet güvenlik olayı tespit edildi.\n")
                print(f"\n[+] Kritik bulgular raporu oluşturuldu: {rapor_adi}")
            else:
                print("\n[+] Ağda herhangi bir anormallik tespit edilmedi. Tüm cihazlar baseline ile uyumlu.")
            

except nmap.PortScannerError:
    print("[-] Nmap motoru sistemde bulunamadı veya çöktü.")
except Exception as e:
    print(f"[-] Beklenmedik bir hata meydana geldi: {e}")
    print("[*] NetSentinel taramayı güvenli bir şekilde sonlandırdı.")

print("\n[*] Adım 1: Çekirdek Tarayıcı Modülü başarıyla tamamlandı!")  

         

    