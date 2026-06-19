# AkademiX

> TAÜ öğrencileri için AI destekli akademik asistan

**[➜ Uygulamayı Aç](https://lefos5.github.io/akademiX)**

---

## Nedir?

AkademiX, Türk-Alman Üniversitesi (TAÜ) öğrencilerinin akademik yaşamını tek bir yerden yönetmesini sağlayan web uygulamasıdır. Google Classroom entegrasyonu, ders materyali yönetimi ve yapay zeka araçlarını bir araya getirir.

## Özellikler

### 📅 Ders Yönetimi
- **Haftalık Program** — Renk kodlu ders takvimi görünümü
- **Derslerim** — Kayıtlı derslerin filtrelenebilir kart görünümü
- **Google Classroom** — Ödev, duyuru ve not takibi (gerçek zamanlı senkronizasyon)

### 📁 Materyal & Notlar
- **Materyaller** — PDF, PPTX, DOCX yükleme ve yönetim
- **Defter** — Derse özel not alma ve düzenleme
- **Takvim** — Etkinlik ve ödev takibi

### 🤖 AI Araçları
- **Sayfa Sayfa Çeviri** — Almanca/İngilizce slaytları Türkçeye çevirir; teknik terimler tıklanabilir tooltip ile orijinal dilde gösterilir
- **Çalışma Notu** — Slayttaki konuları tespit edip her birini açıklayan defter formatında not
- **Sınav Referans Kartı** — Formüller, kavram sözlüğü ve kritik bilgilerin özeti
- **Sınav Oluştur** — Çoktan seçmeli, doğru/yanlış ve açık uçlu karışık sınav
- **RAG Sorgulama** — Yüklenen materyaller üzerinde doğal dil ile arama ve soru cevaplama
- **Sohbet** — Materyal içeriği hakkında AI ile serbest sohbet
- **Akıl Haritası** — Materyalden otomatik kavram haritası

## Teknik Yığın

| Katman | Teknoloji |
|---|---|
| Frontend | Vanilla HTML / CSS / JavaScript (tek dosya) |
| Backend | Vercel Serverless Functions (Node.js) |
| Veritabanı | Supabase (PostgreSQL + Storage) |
| AI | Google Gemini 2.5 Flash (metin + görsel) |
| Embedding | Hugging Face — multilingual MiniLM |
| Auth | Google OAuth 2.0 |
| PDF | PDF.js |
| Belgeler | Mammoth.js (DOCX), SheetJS (XLSX) |

## Kullanım

1. [lefos5.github.io/akademiX](https://lefos5.github.io/akademiX) adresine git
2. **TAÜ kurumsal Google hesabınla** (`@stud.tau.edu.tr` veya `@tau.edu.tr`) giriş yap
3. Derslerini seç, materyal yükle ve AI araçlarını kullan

> ⚠️ Uygulama yalnızca TAÜ kurumsal Google hesaplarına açıktır.

## Gizlilik

Kullanıcı verileri yerel depolama (browser) ve bulut (Supabase) üzerinde saklanır. Üçüncü taraflarla paylaşım yapılmaz. [Gizlilik Politikası](https://lefos5.github.io/akademiX/privacy.html)

## Geliştirici

**lefos5** — TAÜ öğrencisi  
Soru ve geri bildirim: [GitHub Issues](https://github.com/lefos5/akademiX/issues)

---

<p align="center">TAÜ öğrencileri için ❤️ ile yapıldı</p>
