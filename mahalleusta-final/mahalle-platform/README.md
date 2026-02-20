# 🏘️ MahallePro – Mahalle Hizmet Platformu

Kullanıcıların mahalle bazlı güvenilir hizmet verenleri bulmasını sağlayan modern, full-stack web platformu.

---

## 🚀 Hızlı Kurulum

### 1. Gereksinimler
- Python 3.9+
- pip

### 2. Bağımlılıkları Yükle

```bash
cd mahalle-platform
pip install -r requirements.txt
```

### 3. Çalıştır

```bash
python app.py
```

Uygulama `http://localhost:5000` adresinde açılır.

---

## 🔑 Varsayılan Admin Hesabı

| Alan | Değer |
|------|-------|
| E-posta | admin@mahalle.com |
| Şifre | admin123 |

> ⚠️ Production'da mutlaka değiştirin!

---

## 📁 Proje Yapısı

```
mahalle-platform/
├── app.py              # Ana uygulama & factory fonksiyonu
├── models.py           # SQLAlchemy modelleri
├── routes.py           # Tüm route'lar (auth, main, provider, admin)
├── requirements.txt    # Python bağımlılıkları
├── .env                # Ortam değişkenleri
├── templates/
│   ├── base.html       # Ana layout
│   ├── index.html      # Ana sayfa
│   ├── search.html     # Arama sayfası
│   ├── provider_detail.html
│   ├── become_provider.html
│   ├── dashboard.html
│   ├── edit_profile.html
│   ├── login.html
│   ├── register.html
│   └── admin/
│       ├── index.html
│       ├── providers.html
│       ├── users.html
│       └── reviews.html
└── static/
    ├── css/style.css   # Tüm stiller
    ├── js/main.js      # JavaScript
    └── uploads/        # Kullanıcı fotoğrafları
```

---

## ✨ Özellikler

### Kullanıcı Sistemi
- Kayıt ol, giriş yap, çıkış yap
- bcrypt şifre hashleme
- Flask-Login oturum yönetimi

### Hizmet Veren Sistemi
- Profil oluşturma ve düzenleme
- Kategori, konum seçimi
- Fotoğraf yükleme (Pillow ile yeniden boyutlandırma)
- Admin onayı sistemi
- Doğrulanmış hesap rozeti

### Konum Sistemi
- İl / İlçe / Mahalle kademeli seçimi
- AJAX ile dinamik dropdown

### Arama & Filtreleme
- Kategoriye, şehre, ilçeye, mahalleye göre
- İsim ile metin araması

### Yorum & Puanlama
- 1-5 yıldız sistemi
- Ortalama puan otomatik hesaplama
- Sadece giriş yapmış kullanıcılar yorum yapabilir
- Kullanıcı başına 1 yorum limiti

### Admin Paneli
- Hizmet veren onaylama
- Hesap doğrulama rozeti
- Kullanıcı aktif/pasif yönetimi
- Yorum silme
- İstatistik dashboard

---

## 🔒 Güvenlik

- CSRF koruması (Flask-WTF)
- bcrypt şifre hashleme
- SQL injection koruması (SQLAlchemy ORM)
- Form validasyonu
- Dosya tipi kontrolü
- Dosya boyutu limiti (5MB)

---

## 🌐 Production Deployment

### PostgreSQL'e Geçiş

`.env` dosyasında:
```
DATABASE_URL=postgresql://user:pass@host:5432/mahalle_db
```

### Gunicorn ile Çalıştırma

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 "app:create_app()"
```

### Nginx Konfigürasyonu

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /static {
        alias /path/to/mahalle-platform/static;
    }
}
```

---

## 🛠️ Teknoloji Yığını

| Katman | Teknoloji |
|--------|-----------|
| Backend | Python Flask |
| ORM | SQLAlchemy |
| Auth | Flask-Login + bcrypt |
| CSRF | Flask-WTF |
| Frontend | HTML5 + CSS3 + Vanilla JS |
| Fonts | Google Fonts (DM Sans + DM Serif Display) |
| Icons | FontAwesome 6 |
| DB | SQLite (PostgreSQL uyumlu) |
| Görsel | Pillow |
