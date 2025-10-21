# 🕵️ YorHa9S — Security Scanner
### Android Unit 9S - Advanced Security Assessment Tool

![YorHa](https://img.shields.io/badge/YoRHa-9S-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![Security](https://img.shields.io/badge/Security-Scanner-red)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20Windows-lightgrey)

---

## ⚠️ LEGAL NOTICE — BACA SAMPAI HABIS
**SANGAT PENTING:** Alat ini dibuat untuk tujuan **pengujian keamanan yang SAH** (authorized security testing), penelitian, dan pendidikan.

**HANYA untuk:**
- ✅ Testing website / sistem milik sendiri
- ✅ Penetration testing dengan IZIN TERTULIS
- ✅ Lingkungan lab / sandbox pribadi
- ✅ Program bug bounty yang memberikan otorisasi

**DILARANG KERAS untuk:**
- ❌ Aktivitas ilegal atau merugikan pihak lain
- ❌ Mengakses, menyerang, atau mengeksploitasi sistem tanpa izin
- ❌ Menyebarkan exploit/payload ke pihak ketiga tanpa otorisasi

> Penyalahgunaan alat ini dapat menyebabkan tuntutan pidana dan/atau perdata. Penulis dan kontributor **TIDAK BERTANGGUNG JAWAB** atas tindakan ilegal yang dilakukan pengguna. Jika ragu, jangan gunakan.

---

## 📌 Deskripsi Singkat
YorHa9S adalah toolkit pengujian keamanan berbasis pembelajaran mesin yang membantu discovery, fingerprinting, dan penilaian kerentanan pada target **dengan izin**. Tool ini menyediakan modul scanning, reporting, dan monitoring untuk keperluan riset keamanan.

## 🎯 Features
- **Port Scanning** — Deteksi port terbuka
- **Vulnerability Assessment** — Indikator untuk SQLi, XSS, Security Headers
- **WAF Bypass** — Advanced evasion techniques (for research)
- **Stealth Scanning** — Anti-detection & configurable delays
- **Service Detection** — Identifikasi layanan & versi
- **Endpoint Discovery** — Temukan path tersembunyi
- **Comprehensive Reporting** — Laporan dan log terstruktur

> Catatan: Beberapa fitur dapat menghasilkan traffic tinggi — gunakan hanya pada target yang diizinkan.

---

# YorHa9S
> — **Hanya untuk testing dengan IZIN.**

---

## 📦 Instalasi

### Termux (Android)
```bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/XersesAnalyz/YorHa9S.git
cd YorHa9S
pip3 install requests urllib3
python3 YorHa9S.py
```

### 🛠️ Linux / Mac
```bash
sudo apt update && sudo apt install python3 python3-pip git
git clone https://github.com/XersesAnalyz/YorHa9S.git
cd YorHa9S
pip3 install requests urllib3
python3 YorHa9S.py
```

### 🪟 Windows
```powershell
# Install Python 3.8+ dari python.org
# Install Git dari git-scm.com
git clone https://github.com/XersesAnalyz/YorHa9S.git
cd YorHa9S
pip install requests urllib3
python YorHa9S.py
```

---
