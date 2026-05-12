# RSA-OAEP-256 Encryption Tool (2048-bit) — TP Kripto

## Dibuat oleh:
### - Gilbert Kristian
### - Husin Hidayatul Hakim
### - Ivan Jehuda Angi

Implementasi mandiri (full custom, tanpa library kriptografi) skema enkripsi
**RSA-OAEP** dengan padding **OAEP berbasis SHA-256** dan kunci **2048 bit**,
sesuai PKCS#1 v2.2 (RFC 8017). Aplikasi dilengkapi GUI berbasis CustomTkinter
untuk membangkitkan keypair, mengenkripsi, dan mendekripsi file apapun
(teks, gambar, audio, video, executable).

---

## 1. Daftar Isi

- [Fitur](#fitur)
- [Cara Pakai](#cara-pakai)
  - [Instalasi](#instalasi)
  - [Menjalankan GUI](#menjalankan-gui)
  - [Workflow](#workflow)
- [Format File](#format-file)
- [Detail Implementasi](#detail-implementasi)
- [Pengujian](#pengujian)
- [Catatan Performa](#catatan-performa)
- [Library yang Digunakan](#library-yang-digunakan)

---

## Fitur

- Pembangkitan keypair RSA 2048-bit (Miller-Rabin 40 putaran).
- Enkripsi dan dekripsi file **biner apapun** (text, image, audio, video,
  executable). File besar diproses blok demi blok.
- OAEP padding sesuai RFC 8017 (lHash, MGF1, separator 0x01, masked seed/DB).
- Format key sederhana berbasis teks heksadesimal.
- GUI CustomTkinter dengan tab terpisah: **Generate Keys**, **Encrypt**, **Decrypt**.
- Operasi panjang berjalan di thread terpisah, GUI tetap responsif dengan
  progress bar dan status.
- Skrip pengujian roundtrip otomatis (encrypt → decrypt → byte-for-byte compare).

---

## Cara Pakai

### Instalasi

Butuh **Python 3.10+**.

```powershell
pip install -r requirements.txt
```

Hanya satu dependency: `customtkinter` (untuk GUI). Seluruh logika RSA-OAEP
murni Python standar (`hashlib`, `secrets`, `math`, `os`).

### Install Font (Disarankan)
Pada folder `assets/font`, klik file font dan install. 

### Menjalankan GUI

```powershell
python main.py
```

### Workflow

1. **Tab "Generate Keys"**
   - Tentukan path file `public.key` dan `private.key`.
   - Klik **Generate Keypair (2048-bit)**.
   - Tunggu beberapa detik (pembangkitan dua bilangan prima 1024-bit).
   - Dua file key tersimpan dalam format teks hexadecimal.

2. **Tab "Encrypt"**
   - Pilih file plaintext (boleh biner: gambar, video, exe, dll).
   - Pilih file public key.
   - Klik **Encrypt**. Progress bar menunjukkan kemajuan per blok.

3. **Tab "Decrypt"**
   - Pilih file ciphertext.
   - Pilih file private key.
   - Klik **Decrypt**.

Hasil dekripsi pasti identik (byte-for-byte) dengan plaintext asli.

---

## Format File

### Key file (teks ASCII, hexadecimal)

```
<n_hex>            (modulus, 2048 bit ≈ 512 char hex)
<e_hex_atau_d_hex> (eksponen)
```

- File public key: baris 1 = `n`, baris 2 = `e` (umumnya `10001` = 65537).
- File private key: baris 1 = `n`, baris 2 = `d`.

### Ciphertext file (raw biner)

Rangkaian blok 256-byte, masing-masing adalah hasil RSA-OAEP dari maksimum
190 byte plaintext (chunked encryption). Total ukuran ciphertext selalu
kelipatan 256.

Contoh: plaintext 1 KB → 6 blok ciphertext → 1536 byte total.

---

## Detail Implementasi

### Pembangkitan Kunci

```
p, q  ← random prime 1024-bit (Miller-Rabin, 40 rounds)
n     ← p · q                          (2048-bit)
e     ← 65537
λ(n)  ← lcm(p−1, q−1)                  (Carmichael's totient)
d     ← e⁻¹ mod λ(n)                   (extended Euclidean)
public  = (n, e)
private = (n, d)
```

### OAEP Encode (per blok ≤ 190 byte)

```
lHash    = SHA256(label="")            (32 byte)
PS       = 0x00 ... 0x00               (k − mLen − 2·hLen − 2 byte)
DB       = lHash || PS || 0x01 || M    (k − hLen − 1 byte)
seed     = random 32 byte
dbMask   = MGF1(seed, k − hLen − 1)
maskedDB = DB ⊕ dbMask
seedMask = MGF1(maskedDB, hLen)
maskedSeed = seed ⊕ seedMask
EM       = 0x00 || maskedSeed || maskedDB
```

`EM` lalu dikonversi ke integer `m`, dan ciphertext `c = m^e mod n`,
kemudian ditulis sebagai 256 byte big-endian.

### OAEP Decode

Membalik proses di atas dan memverifikasi:
- byte pertama harus `0x00`,
- `lHash'` harus sama dengan `lHash`,
- harus ditemukan separator `0x01` setelah string nol.

Bila salah satu cek gagal, dekripsi dianggap error.

### Chunked File Encryption

Plaintext dipecah menjadi blok-blok berukuran maksimum **190 byte**
(`k − 2·hLen − 2` untuk k=256, hLen=32). Tiap blok:
1. di-OAEP-encode dengan seed acak baru,
2. di-RSA-encrypt menjadi blok ciphertext 256 byte,
3. ditulis berurutan ke file output.

Karena setiap blok memakai seed acak, dua plaintext identik menghasilkan
ciphertext yang berbeda — sifat keamanan OAEP.

---

## Pengujian

```powershell
python tests/test_roundtrip.py
```

Skrip akan:
1. Membangkitkan keypair 2048-bit.
2. Menguji save/load key file.
3. Melakukan enkripsi → dekripsi pada beberapa kasus uji (kosong, 1 byte,
   tepat 190 byte, lintas blok 191 byte, 380 byte, teks UTF-8, biner acak
   4 KB dan 64 KB).
4. Bila ada file di `tests/samples/`, semua file tersebut juga diuji.

Untuk menguji jenis file yang diminta tugas (text, image, audio, video,
executable), letakkan file uji ke folder `tests/samples/`, contoh:

```
tests/samples/
├── file.txt
├── photo.jpg
├── song.mp3
├── clip.mp4
└── tool.exe
```

Kemudian jalankan ulang skrip pengujian. Setiap file akan dienkripsi
lalu didekripsi, dan hasilnya dibandingkan byte-for-byte dengan aslinya.

Hasil pengujian internal:

```
[PASS] empty                               size=         0 B
[PASS] 1 byte                              size=         1 B
[PASS] 190 bytes (1 chunk full)            size=       190 B
[PASS] 191 bytes (cross-chunk)             size=       191 B
[PASS] 380 bytes (exactly 2)               size=       380 B
[PASS] text utf-8                          size=       260 B
[PASS] random binary 4 KB                  size=      4096 B
[PASS] random binary 64 KB                 size=     65536 B
ALL PASS
```

---

## Catatan Performa

Karena seluruh aritmetika RSA dijalankan di Python pure (memanfaatkan
`pow(a, b, n)` built-in untuk modular exponentiation), kecepatan terbatas:

| Operasi              | ~Kecepatan          |
|----------------------|---------------------|
| Key generation       | 1–5 detik           |
| Enkripsi (e=65537)   | ~ratusan KB/detik   |
| Dekripsi (d besar)   | ~beberapa KB/detik  |

Untuk file kecil (dokumen, gambar kecil, sampel audio pendek) kinerja
nyaman. Untuk file video/audio berukuran besar (puluhan MB ke atas)
akan sangat lambat — ini adalah karakteristik RSA murni dan bukan bug.
Jika perlu performa tinggi, biasanya digunakan skema hybrid (RSA + AES),
namun tugas ini secara spesifik meminta RSA-OAEP-256, sehingga skema
chunked RSA murni dipakai di sini.

---

## Library yang Digunakan

- **`hashlib`** (Python stdlib) — SHA-256 untuk OAEP. Bukan library
  kriptografi pihak ketiga, melainkan modul standar Python.
- **`secrets`** (Python stdlib) — RNG aman secara kriptografis untuk
  pembangkitan prima dan OAEP seed.
- **`math.gcd`** (Python stdlib) — fungsi gcd umum.
- **`customtkinter`** — hanya untuk GUI; tidak menyentuh logika kripto.

Semua primitif kriptografi (Miller-Rabin, prime generation, modular
inverse, RSA encrypt/decrypt, OAEP encode/decode, MGF1, I2OSP, OS2IP)
**diimplementasikan sendiri** di `rsa_core.py` dan `oaep.py`.

---