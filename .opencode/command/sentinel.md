---
description: Hedef bir IP veya alan adının açıklarını ve gereçlerini (kaynaklarını) bulur.
agent: build
---

SENTINEL-X ile `$ARGUMENTS` hedefini değerlendir. Hedef IP adresi ya da alan adı olabilir.

Hedef: **$ARGUMENTS**

## Kapsam

Sunucu yalnızca `SENTINELX_SCOPE_TARGETS` içindeki hedefleri kabul eder. İlk iş olarak
`$ARGUMENTS` bu kapsamın içinde mi diye bak:

- Kapsam dışıysa **hiçbir araç çağırma**. Kullanıcıya sunucunun kapsam listesini ver ve
  listeye eklemesini iste. Kapsam dışı bir hedefe istek göndererek engeli aşmak, aracın
  var olma sebebini ortadan kaldırır.
- Kapsam içindeyse devam et.

## Değerlendirme sırası

Hedef bir alan adıysa bu sırayı izle. Bir IP adresiyse 1. adımda dur ve 2'den başla.

1. **Sahiplik ve kayıt** — `sentinelx_whois_lookup`, `sentinelx_dns_lookup`.
   Kimin varlığı olduğunu ve nereye bakacağını bilmeden bulgu sıralamak yanlış öncelik demektir.

2. **Açık portlar ve sürümler** — `sentinelx_port_scan` (önce `standard` profil).
   Her açık servis için sürüm parmak izini `sentinelx_version_risk` ile NVD'ye karşılaştır.

3. **DNS ve alt alan adları** (yalnız alan adı) — `sentinelx_dns_security_audit`,
   `sentinelx_subdomain_discovery`.

4. **Web yüzeyi** — keşfedilen her host için `sentinelx_http_probe` (toplu, tek çağrıda
   hepsini birden). Ardından ilginç olanlar için `sentinelx_tls_audit`.

5. **Arşivlenmiş yollar** (yalnız alan adı) — `sentinelx_url_archive` ile geçmişte
   görünen yollar; günümüzde kapalı olsalar bile saldırı yüzeyi hakkında fikir verir.

6. **Yerel yapılandırma** (yalnız bu makinenin kendi diski isteniyorsa) —
   `sentinelx_secret_scan`, `sentinelx_config_audit`, `sentinelx_host_posture_audit`.

## Raporlarken

- **Gördüğün ile çıkardığını ayır.** Bir sürüm parmak izini *hipotezdir*, kanıt değil.
  CPE eşleşmesi *korelasyondur*, istismar kanıtı değildir. Aynı şekilde "yanıt yok"
  ile "kapsam dışı olduğu için sorulmadı" farklı şeylerdir ve hangisi olduğunu yaz.
- **Açık dedikten önce kanıt iste.** Bir başlık eksikliği açık değil, yapılandırma
  eksiğidir. Yalnızca sömürülebilirliği gösterilmiş bir bulguyu açık olarak adlandır.
- **Kaynak başarısız olduysa bunu raporla.** Bir kaynak "veri yok" değil, "yanıt vermedi"
  demektir. Aradaki farkı yazmadan sonuç eksik görünür.
- **Önceliği etkiye göre ver**, taramaya göre değil. Etkilenebilir bir serviste
  sömürülebilir bulgu, üç ayrı hostta başlık eksiğinden önce gelir.
- Bulgu yoksa **"bulgu yok" demek yerine neye baktığını ve bakmadığın ne olduğunu yaz.**
  Kapsamlı bir taramayla da bir şey bulunmayabilir; bunu "temiz" diye sunmak yanlış olur.

Çıktıyı Türkçe ver. Her bulgu için: ne, kanıtı, etkisi, düzeltme önerisi.
