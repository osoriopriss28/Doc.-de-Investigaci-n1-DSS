import os
import hmac
import hashlib
import secrets
import base64
from dataclasses import dataclass, field
from typing import List, Tuple

# Utilidades

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def from_b64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

def keystream_from_seed(seed: bytes, n: int) -> bytes:
    """
    Expande 64 bits (8 bytes) a n bytes usando SHA-256 en modo contador.
    *No es OTP perfecto* (porque extiende), pero es práctico para laboratorio.
    Para OTP verdadero, la llave debe ser >= longitud del mensaje.
    """
    out = bytearray()
    counter = 0
    while len(out) < n:
        counter_bytes = counter.to_bytes(8, "big")
        out.extend(hashlib.sha256(seed + counter_bytes).digest())
        counter += 1
    return bytes(out[:n])

# Tabla de llaves
@dataclass
class KeyRow:
    key_id: int
    key: bytes          
    used: bool = False  

@dataclass
class KeyTable:
    rows: List[KeyRow] = field(default_factory=list)
    cursor: int = 0

    @staticmethod
    def generate(n: int = 32, bits: int = 64) -> "KeyTable":
        if bits % 8 != 0:
            raise ValueError("bits debe ser múltiplo de 8")
        rows = []
        for i in range(n):
            k = secrets.token_bytes(bits // 8)
            rows.append(KeyRow(key_id=i, key=k, used=False))
        return KeyTable(rows=rows, cursor=0)

    def next_key(self, mark_used: bool = True) -> KeyRow:
        if self.cursor >= len(self.rows):
            raise RuntimeError("Sin llaves disponibles. Genere más.")
        row = self.rows[self.cursor]
        if mark_used:
            row.used = True
        self.cursor += 1
        return row

    def get_key_by_id(self, key_id: int) -> KeyRow:
        return self.rows[key_id]

    def reset_usage(self):
        for r in self.rows:
            r.used = False
        self.cursor = 0


# Cifrado / Descifrado

def encrypt_message(msg: str, key64: bytes, strict_otp: bool = False) -> bytes:
    m = msg.encode("utf-8")
    if strict_otp:
        if len(key64) < len(m):
            raise ValueError("Para OTP estricto, la llave debe ser >= mensaje.")
        ks = key64[:len(m)]
    else:
        ks = keystream_from_seed(key64, len(m))
    return xor_bytes(m, ks)

def decrypt_message(ct: bytes, key64: bytes, strict_otp: bool = False) -> str:
    if strict_otp:
        if len(key64) < len(ct):
            raise ValueError("Para OTP estricto, la llave debe ser >= cifrado.")
        ks = key64[:len(ct)]
    else:
        ks = keystream_from_seed(key64, len(ct))
    pt = xor_bytes(ct, ks)
    return pt.decode("utf-8")

# Autenticación (HMAC)
def hmac_tag(data: bytes, key64: bytes) -> bytes:
    mac_key = hashlib.sha256(b"MAC|" + key64).digest()
    return hmac.new(mac_key, data, hashlib.sha256).digest()

def verify_hmac(data: bytes, tag: bytes, key64: bytes) -> bool:
    mac_key = hashlib.sha256(b"MAC|" + key64).digest()
    return hmac.compare_digest(hmac.new(mac_key, data, hashlib.sha256).digest(), tag)

# Intercambios

def intercambio_directo(msg: str, kt: KeyTable, strict_otp: bool = False) -> Tuple[str, str, str, int]:
    row = kt.next_key(mark_used=True)
    ct = encrypt_message(msg, row.key, strict_otp)
    pt = decrypt_message(ct, row.key, strict_otp)
    return msg, b64(ct), pt, row.key_id

def intercambio_polimorfico(msgs: List[str], kt: KeyTable, strict_otp: bool = False) -> List[Tuple[int, str, str]]:
    """
    Envía varios mensajes, rotando la llave por mensaje (polimórfico).
    Devuelve lista de (key_id, ct_b64, pt).
    """
    results = []
    for m in msgs:
        row = kt.next_key(mark_used=True)
        ct = encrypt_message(m, row.key, strict_otp)
        pt = decrypt_message(ct, row.key, strict_otp)
        results.append((row.key_id, b64(ct), pt))
    return results

def intercambio_autenticado(msg: str, kt: KeyTable, strict_otp: bool = False) -> Tuple[int, str, str, str]:
    """
    Cifra + etiqueta HMAC. Receptor verifica HMAC, luego descifra.
    Devuelve (key_id, ct_b64, tag_b64, pt).
    """
    row = kt.next_key(mark_used=True)
    ct = encrypt_message(msg, row.key, strict_otp)
    tag = hmac_tag(ct, row.key)
    ok = verify_hmac(ct, tag, row.key)
    if not ok:
        raise RuntimeError("Fallo de autenticidad (HMAC).")
    pt = decrypt_message(ct, row.key, strict_otp)
    return row.key_id, b64(ct), b64(tag), pt

# CLI de demostración

def print_header(title: str):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)

def demo():
    kt = KeyTable.generate(n=64, bits=64)

    while True:
        os.system("cls")
        print("------------------------------------------------------------")
        print("|                TP Polimórfico - Demo                     |")   
        print("------------------------------------------------------------")                 
        print("|   1) Intercambio directo (A -> B)                        |")
        print("|   2) Intercambio polimórfico (rotación por mensaje)      |")
        print("|   3) Intercambio autenticado (cifrado + HMAC)            |")
        print("|   4) Regenerar tabla de llaves                           |")
        print("|   5) Resetear uso / cursor                               |")
        print("|   0) Salir                                               |")
        print("------------------------------------------------------------")
        choice = input("Elige opción: ").strip()

        if choice == "1":
            print_header("Intercambio directo")
            msg = input("Mensaje a cifrar: ")
            print("--------------------------------------------------")
            strict = input("OTP estricto (s/n)? ").lower().startswith("s")
            try:
                m, ct_b64, pt, key_info = intercambio_directo(msg, kt, strict_otp=strict)
                print("--------------------------------------------------")
                print(f"|{key_info}")
                print(f"|Mensaje original: | {m}")
                print("----------------------------------------------")
                print(f"|Cifrado (base64): | {ct_b64} ")
                print("----------------------------------------------")
                print(f"|Descifrado:       | {pt}")
                print("----------------------------------------------")
                print("|✓ Claro y correcto.\n")
                print("----------------------------------------------|")
            except Exception as e:
                print("Error:", e)
            input("Preciona ENTER para continuar...")

        elif choice == "2":
            print_header("Intercambio polimórfico")            
            print("--------------------------------------------------")
            strict = input("OTP estricto (s/n)? ").lower().startswith("s")
            try:
                
                print("--------------------------------------------------")
                n = int(input("¿Cuántos mensajes? "))                
                print("--------------------------------------------------")
                msgs = [input(f"Ingrese el mensaje #{i+1}: ") for i in range(n)]
                results = intercambio_polimorfico(msgs, kt, strict_otp=strict)                
                print("--------------------------------------------------")
                for (original, ct_b64, pt, key_info) in results:
                    
                    print("--------------------------------------------------")
                    print(f"{key_info}")                    
                    print("--------------------------------------------------")
                    print(f"|  Original: |  {original}")            
                    print("--------------------------------------------------")
                    print(f"|  Cifrado:    | {ct_b64}")            
                    print("--------------------------------------------------")
                    print(f"|  Descifrado: |{pt}")            
                    print("--------------------------------------------------")
                    print("✓ Rotación polimórfica aplicada.\n")            
                    print("--------------------------------------------------")
            except Exception as e:
                print("Error:", e)
            input("Preciona ENTER para continuar...")

        elif choice == "3":
            print_header("Intercambio autenticado")
            print("--------------------------------------------------")
            msg = input("Ingrese el mensaje a cifrar: ")
            print("--------------------------------------------------")
            strict = input("OTP estricto (s/n)? ").lower().startswith("s")
            try:
                key_info, ct_b64, tag_b64, pt = intercambio_autenticado(msg, kt, strict_otp=strict)
                print("--------------------------------------------------")
                print(f"|{key_info}")
                print("--------------------------------------------------")
                print(f"|Cifrado (base64):      | {ct_b64}")
                print("--------------------------------------------------")
                print(f"|Etiqueta HMAC (base64):| {tag_b64}")
                print("--------------------------------------------------")
                print(f"|Descifrado:            | {pt}")
                print("--------------------------------------------------")
                print("✓ Autenticidad verificada con HMAC.\n")
                print("--------------------------------------------------")
            except Exception as e:
                print("Error:", e)
            input("Preciona ENTER para continuar...")

        elif choice == "4":
            print_header("Regenerar tabla de llaves")
            
            try:
                n = int(input("Cantidad de llaves: "))
                print("--------------------------------------------------")
                kt = KeyTable.generate(n=n, bits=64)
                print(f"✓ Tabla regenerada con {n} llaves de 64 bits.\n")
                print("--------------------------------------------------")
            except Exception as e:
                print("Error:", e)
            input("Precione ENTER para continuar...")

        elif choice == "5":
            kt.reset_usage()
            print("✓ Uso/cursor reseteados.\n")
            print("--------------------------------------------------")
            input("Precione ENTER para continuar...")

        elif choice == "0":
            print("Programa finalizado")
            break
        else:
            print("Opción no válida.\n")
            input("Precione ENTER para continuar...")
if __name__ == "__main__":
    demo()
