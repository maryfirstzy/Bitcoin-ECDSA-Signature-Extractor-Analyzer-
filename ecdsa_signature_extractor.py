import re

# Fikcyjne dane
address = "bc1qcpflj68s3ahy4xajez4d8v3vk28pvf7qte2jmlftvxzfke2u6mqsge3gvh  "
z = "f8a1b5c089a029321f14b24b1a25b43201e94c82cd5fa9ef59e8b345cf8adab3"
SIGHASH_FLAG = 94
txid = "20644af039cc383818a504bd5822ef0ff7cd22773a8b22dd8f86677bcfad1e36"

# Otwieramy plik i czytamy dane
with open(r"C:\Users\wywol\Desktop\Nowy Dokument tekstowy (3).txt", "r") as f:
    hex_data = f.read().strip()

# Wyrażenie regularne dla DER podpisu:
pattern = re.compile(r'(30[\da-fA-F]{2}02[\da-fA-F]{2}[\da-fA-F]{2,66}02[\da-fA-F]{2}[\da-fA-F]{2,66})')

matches = pattern.findall(hex_data)
print("Znaleziono podpisów:", len(matches))

# Funkcja do wyodrębniania r i s
def parse_der(sig_hex):
    r_len = int(sig_hex[6:8], 16)
    r_val = sig_hex[8:8+r_len*2]
    s_marker_index = 8 + r_len*2
    if sig_hex[s_marker_index:s_marker_index+2] != "02":
        return None, None
    s_len = int(sig_hex[s_marker_index+2:s_marker_index+4], 16)
    s_val = sig_hex[s_marker_index+4:s_marker_index+4+s_len*2]
    return r_val, s_val

parsed_signatures = []
for m in matches:
    r_val, s_val = parse_der(m)
    if r_val is not None and s_val is not None:
        parsed_signatures.append((r_val, s_val))

print("Zparsowano podpisów:", len(parsed_signatures))

# Zapisanie podpisów w pożądanym formacie
for idx, (r, s) in enumerate(parsed_signatures, start=1):
    # Drukowanie każdego podpisu w odpowiednim formacie, bez numerowania "Podpis 1", "Podpis 2" itd.
    print(f"Adres: {address}")
    print(f"r = {r}")
    print(f"s = {s}")
    print(f"z = {z}")
    print(f"SIGHASH_FLAG = {SIGHASH_FLAG}")
    print(f"txid = {txid}")
    print("Podatności: Reuse k w różnych podpisach")
    print("----------------------------------")
