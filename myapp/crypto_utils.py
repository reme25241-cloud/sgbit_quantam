# users/crypto_utils.py
import os, hashlib, secrets, base64, json
from typing import Tuple, Dict, Optional

# ---------- Exceptions ----------
class CryptoConfigError(ValueError):
    """Raised when required crypto keys/config are missing or invalid."""
    pass

# ---------- PQ backends discovery ----------
KYBER_BACKEND = None  # "pqcrypto" | "oqs" | None
DILITHIUM_BACKEND = None  # "pqcrypto" | None (Ed25519 fallback)

try:
    # Primary backend: pqcrypto (Kyber + Dilithium)
    from pqcrypto.kem.kyber512 import (
        generate_keypair as kyber_generate,
        encapsulate as kyber_encapsulate,
        decapsulate as kyber_decapsulate,
    )
    from pqcrypto.sign.dilithium2 import (
        generate_keypair as dilithium_generate,
        sign as dilithium_sign,
        verify as dilithium_verify,
    )
    KYBER_BACKEND = "pqcrypto"
    DILITHIUM_BACKEND = "pqcrypto"
except Exception:
    try:
        # Secondary backend: OQS for Kyber only (pip install pyoqs)
        import oqs  # type: ignore
        KYBER_BACKEND = "oqs"
        # (You can switch DILITHIUM_BACKEND to "oqs" if you add sign/verify below)
        DILITHIUM_BACKEND = None
    except Exception:
        KYBER_BACKEND = None
        DILITHIUM_BACKEND = None

def PQ_KEM_AVAILABLE() -> bool:
    return KYBER_BACKEND is not None

def PQ_SIGN_AVAILABLE() -> bool:
    return DILITHIUM_BACKEND is not None

# ---------- Symmetric ciphers ----------
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ---------- Signatures (fallback: Ed25519) ----------
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization

# ---------- Utilities ----------
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: Optional[str]) -> bytes:
    if not s:
        raise CryptoConfigError("Missing required base64 string (got None/empty).")
    return base64.b64decode(s.encode())

# ---------- KEM (Kyber or simulated) ----------
def kem_generate(use_pq: bool = True) -> Dict:
    """
    Generate a KEM keypair.
    - If use_pq=True and a PQ backend exists -> Kyber keys
    - Else -> simulated random keys (demo only)
    """
    if use_pq and KYBER_BACKEND == "pqcrypto":
        pk, sk = kyber_generate()
        return {"pk": b64(pk), "sk": b64(sk), "pq": True, "backend": "pqcrypto"}
    elif use_pq and KYBER_BACKEND == "oqs":
        with oqs.KeyEncapsulation("Kyber512") as kem:  # type: ignore
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return {"pk": b64(pk), "sk": b64(sk), "pq": True, "backend": "oqs"}
    else:
        # Simulated KEM (for environments without PQ libs)
        pk = secrets.token_bytes(800)
        sk = secrets.token_bytes(2400)
        return {"pk": b64(pk), "sk": b64(sk), "pq": False, "backend": "sim"}

def kem_encapsulate(pk_b64: str, force_pq: bool = True) -> Tuple[str, str, bool]:
    """
    Encapsulate to recipient public key.
    Returns (kem_ct_b64, shared_secret_b64, pq_used)
    """
    pk = ub64(pk_b64)
    if force_pq and KYBER_BACKEND == "pqcrypto":
        ct, ss = kyber_encapsulate(pk)
        return b64(ct), b64(ss), True
    elif force_pq and KYBER_BACKEND == "oqs":
        with oqs.KeyEncapsulation("Kyber512") as kem:  # type: ignore
            ct, ss = kem.encap_secret(pk)
        return b64(ct), b64(ss), True
    else:
        # --- Simulated KEM (demo) ---
        # Build ct_bytes that *includes* the nonce so the receiver can reproduce ss.
        nonce = secrets.token_bytes(32)
        h = hashlib.sha3_256(pk + nonce).digest()
        ct_bytes = nonce + h                     # <— ciphertext we store/transmit
        ss = hashlib.sha3_256(ct_bytes).digest() # <— both sides derive the same ss
        return b64(ct_bytes), b64(ss), False     # pq_used=False in simulated mode


def kem_decapsulate(sk_b64: str, ct_b64: str, force_pq: bool = True) -> Tuple[str, bool]:
    sk = ub64(sk_b64)
    ct = ub64(ct_b64)
    if force_pq and KYBER_BACKEND == "pqcrypto":
        ss = kyber_decapsulate(sk, ct); return b64(ss), True
    elif force_pq and KYBER_BACKEND == "oqs":
        with oqs.KeyEncapsulation("Kyber512") as kem:  # type: ignore
            kem.import_secret_key(sk); ss = kem.decap_secret(ct); return b64(ss), True
    else:
        # ct_bytes = nonce || sha3(pk||nonce); ss = sha3(ct_bytes)
        ss = hashlib.sha3_256(ct).digest()
        return b64(ss), False

# ---------- Symmetric encryption helpers ----------
def derive_sym_key(shared_secret_b64: str, info: bytes = b'session-key', length: int = 32) -> bytes:
    """
    HKDF-like derivation (demo). For production, prefer cryptography.hazmat.primitives.kdf.hkdf.HKDF.
    """
    ss = ub64(shared_secret_b64)
    prk = hashlib.pbkdf2_hmac("sha256", ss, b"pq-salt", iterations=1000, dklen=32)
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hashlib.sha256(t + info + bytes([counter]) + prk).digest()
        out += t
        counter += 1
    return out[:length]

def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> Tuple[str, str]:
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return b64(nonce), b64(ct)

def decrypt_aes_gcm(nonce_b64: str, ct_b64: str, key: bytes) -> bytes:
    nonce = ub64(nonce_b64)
    ct = ub64(ct_b64)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

def encrypt_chacha20(plaintext: bytes, key: bytes) -> Tuple[str, str]:
    nonce = os.urandom(12)
    ch = ChaCha20Poly1305(key)
    ct = ch.encrypt(nonce, plaintext, None)
    return b64(nonce), b64(ct)

def decrypt_chacha20(nonce_b64: str, ct_b64: str, key: bytes) -> bytes:
    nonce = ub64(nonce_b64)
    ct = ub64(ct_b64)
    ch = ChaCha20Poly1305(key)
    return ch.decrypt(nonce, ct, None)

# ---------- Hash ----------
def sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()

# ---------- Signatures ----------
def generate_sign_keypair(use_pq: bool = True) -> Dict:
    """
    Generate a signature keypair.
    - If use_pq=True and Dilithium backend is available -> Dilithium
    - Else -> Ed25519
    """
    if use_pq and DILITHIUM_BACKEND == "pqcrypto":
        pk, sk = dilithium_generate()
        return {"pk": b64(pk), "sk": b64(sk), "pq": True, "backend": "pqcrypto"}
    else:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        sk_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {"pk": b64(pk_raw), "sk": b64(sk_raw), "pq": False, "backend": "ed25519"}

def sign_message_hash(hash_bytes: bytes, sk_b64: str, pq_sign: bool) -> str:
    """
    Sign a message hash using Dilithium (if available and chosen) or Ed25519.
    """
    if pq_sign and DILITHIUM_BACKEND == "pqcrypto":
        sk = ub64(sk_b64)
        sig = dilithium_sign(sk, hash_bytes)
        return b64(sig)
    else:
        priv = Ed25519PrivateKey.from_private_bytes(ub64(sk_b64))
        sig = priv.sign(hash_bytes)
        return b64(sig)

def verify_message_hash(hash_bytes: bytes, sig_b64: str, pk_b64: str, pq_sign: bool) -> bool:
    """
    Verify a message hash using Dilithium (if available and used) or Ed25519.
    """
    sig = ub64(sig_b64)
    pk = ub64(pk_b64)
    if pq_sign and DILITHIUM_BACKEND == "pqcrypto":
        try:
            return dilithium_verify(pk, sig, hash_bytes)
        except Exception:
            return False
    else:
        try:
            pub = Ed25519PublicKey.from_public_bytes(pk)
            pub.verify(sig, hash_bytes)
            return True
        except Exception:
            return False

# ---------- Send/Receive convenience ----------
def secure_send_plaintext(
    plaintext: str,
    recipient_kem_pk_b64: str,
    sender_sign_sk_b64: str,
    sender_sign_pk_b64: Optional[str] = None,
    use_pq_kem: bool = True,
    use_pq_sign: bool = True,
    sym_algo: str = 'AES'
) -> Dict:
    """
    Encrypts + signs plaintext and returns a JSON-serializable metadata dict.

    Stored fields:
      kem_ct, ss (DEMO ONLY), pq_kem, pq_sign, sym_algo, nonce, ciphertext,
      hash_hex, signature, signer_pk
    """
    if not recipient_kem_pk_b64:
        raise CryptoConfigError("Recipient has no KEM public key (kem_pk).")

    # KEM (PQ or classical)
    kem_ct_b64, ss_b64, pq_kem_used = kem_encapsulate(
        recipient_kem_pk_b64,
        force_pq=(use_pq_kem and PQ_KEM_AVAILABLE())
    )
    sym_key = derive_sym_key(ss_b64)

    # Symmetric encryption
    pt = plaintext.encode('utf-8')
    algo = (sym_algo or 'AES').upper()
    if algo == 'AES':
        nonce_b64, ct_b64 = encrypt_aes_gcm(pt, sym_key)
    elif algo == 'CHACHA20':
        nonce_b64, ct_b64 = encrypt_chacha20(pt, sym_key)
    else:
        raise CryptoConfigError(f"Unsupported sym_algo: {sym_algo}")

    # Hash + Sign
    h = sha3_256_hex(pt).encode()
    pq_sign_used = bool(use_pq_sign and PQ_SIGN_AVAILABLE())
    sig_b64 = sign_message_hash(h, sender_sign_sk_b64, pq_sign=pq_sign_used)

    # Include signer_pk for self-contained verification
    if not sender_sign_pk_b64:
        if not pq_sign_used:
            # Derive Ed25519 public key from the provided private key
            priv = Ed25519PrivateKey.from_private_bytes(ub64(sender_sign_sk_b64))
            pub = priv.public_key()
            sender_sign_pk_b64 = b64(pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ))
        else:
            # With Dilithium we expect pk to be passed by caller ideally
            sender_sign_pk_b64 = ""

    return {
        "kem_ct": kem_ct_b64,
        "ss": ss_b64,                    # DEMO ONLY — DO NOT store in production
        "pq_kem": pq_kem_used,
        "pq_sign": pq_sign_used,
        "sym_algo": algo,
        "nonce": nonce_b64,
        "ciphertext": ct_b64,
        "hash_hex": h.decode(),
        "signature": sig_b64,
        "signer_pk": sender_sign_pk_b64 or "",
    }

def secure_receive_message(
    recipient_kem_sk_b64: str,
    stored_meta: Dict,
    fallback_signer_pk_b64: Optional[str] = None
) -> Tuple[str, bool]:
    """
    Decrypts and verifies a stored message meta blob.
    Returns (plaintext_str, signature_valid).
    """
    if not recipient_kem_sk_b64:
        raise CryptoConfigError("Recipient has no KEM secret key (kem_sk).")

    pq_kem_used = bool(stored_meta.get("pq_kem", True))
    ss_b64, _ = kem_decapsulate(
        recipient_kem_sk_b64,
        stored_meta["kem_ct"],
        force_pq=(pq_kem_used and PQ_KEM_AVAILABLE())
    )
    sym_key = derive_sym_key(ss_b64)

    algo = stored_meta.get("sym_algo", "AES").upper()
    if algo == "AES":
        pt = decrypt_aes_gcm(stored_meta["nonce"], stored_meta["ciphertext"], sym_key)
    elif algo == "CHACHA20":
        pt = decrypt_chacha20(stored_meta["nonce"], stored_meta["ciphertext"], sym_key)
    else:
        raise CryptoConfigError(f"Unsupported sym_algo in stored meta: {algo}")

    # Verify signature
    h = sha3_256_hex(pt).encode()
    pq_sign_used = bool(stored_meta.get("pq_sign", False))
    signer_pk = stored_meta.get("signer_pk") or fallback_signer_pk_b64
    if not signer_pk:
        raise CryptoConfigError("Missing signer public key to verify signature.")
    sig_valid = verify_message_hash(h, stored_meta["signature"], signer_pk, pq_sign=pq_sign_used)

    return pt.decode('utf-8'), sig_valid
