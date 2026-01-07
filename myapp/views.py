# users/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required

from django.db.models import Q
from django.conf import settings

from django.contrib.auth import get_user_model

from .forms import *
from .models import *

def base(request):
    return render(request, 'base.html')

def signup_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('dashboard')  # Redirect to dashboard after signup
        else:
            # If form is not valid, it will pass validation errors back to the template
            return render(request, 'registration/signup.html', {'form': form})
    else:
        form = CustomUserCreationForm()
    
    # If the form is accessed via GET (for example, on initial page load)
    return render(request, 'registration/signup.html', {'form': form})


# Handle user logout
def logout_view(request):
    logout(request)
    return redirect('login')

# profile
@login_required
def profile_view(request):
    return render(request, 'account/profile.html', {'user': request.user})

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import ProfileForm

@login_required
def edit_profile(request):
    user = request.user  # Get the current logged-in user

    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=user)  # Pre-fill the form with user's current data
        if form.is_valid():
            form.save()  # Save the updated data to the database
            return redirect('profile')  # Redirect to profile page (or dashboard, etc.)
    else:
        form = ProfileForm(instance=user)  # Display the form with user's current data

    return render(request, 'account/edit_profile.html', {'form': form})


# dashboard
# users/views.py (add this code)
import json
from collections import Counter, defaultdict
from django.utils import timezone
from datetime import timedelta

from .crypto_utils import secure_receive_message, CryptoConfigError
from .models import Message, CustomUser

# users/views.py (add imports near top)
from collections import Counter
from django.contrib.auth.decorators import login_required
from django.db.models import Q
import json

from .models import Message

@login_required
def dashboard(request):
    """
    Security dashboard:
    - Charts: PQ-KEM vs classical, PQ-sign vs classical, Symmetric algorithm usage
    - Roles/importance & attacker challenges (static explainer blocks)
    - Metadata meaning (inspector of recent messages)
    """
    # Only messages the current user is involved in
    msgs = Message.objects.filter(
        Q(sender=request.user) | Q(receiver=request.user)
    ).order_by('-timestamp')

    total_msgs = msgs.count()

    # Defensive extraction
    def meta(msg):
        return msg.encrypted_meta or {}

    # Aggregates
    pq_kem_count = sum(1 for m in msgs if meta(m).get('pq_kem') is True)
    classical_kem_count = sum(1 for m in msgs if meta(m).get('pq_kem') is False)

    pq_sign_count = sum(1 for m in msgs if meta(m).get('pq_sign') is True)
    classical_sign_count = sum(1 for m in msgs if meta(m).get('pq_sign') is False)

    sym_counter = Counter((meta(m).get('sym_algo') or 'UNKNOWN') for m in msgs)
    # Lock the order we want to display
    sym_labels = ['AES', 'CHACHA20', 'UNKNOWN']
    sym_data = [sym_counter.get(lbl, 0) for lbl in sym_labels]

    # A small metadata inspector (latest 10 messages)
    recent_meta = []
    for m in msgs[:10]:
        em = meta(m)
        recent_meta.append({
            "id": m.id,
            "when": m.timestamp.strftime("%Y-%m-%d %H:%M"),
            "from": getattr(m.sender, "name", str(m.sender)),
            "to": getattr(m.receiver, "name", str(m.receiver)) if m.receiver else "Group",
            "pq_kem": em.get("pq_kem"),
            "pq_sign": em.get("pq_sign"),
            "sym_algo": em.get("sym_algo"),
            "kem_ct": (em.get("kem_ct") or "")[:24] + ("..." if em.get("kem_ct") else ""),
            "nonce": (em.get("nonce") or "")[:16] + ("..." if em.get("nonce") else ""),
            "ciphertext": (em.get("ciphertext") or "")[:24] + ("..." if em.get("ciphertext") else ""),
            "hash_hex": (em.get("hash_hex") or "")[:16] + ("..." if em.get("hash_hex") else ""),
            "signature": (em.get("signature") or "")[:24] + ("..." if em.get("signature") else ""),
            "signer_pk": (em.get("signer_pk") or "")[:24] + ("..." if em.get("signer_pk") else ""),
        })

    context = {
        "total_msgs": total_msgs,
        "pq_kem_count": pq_kem_count,
        "classical_kem_count": classical_kem_count,
        "pq_sign_count": pq_sign_count,
        "classical_sign_count": classical_sign_count,
        "sym_labels": json.dumps(sym_labels),
        "sym_data": json.dumps(sym_data),
        "recent_meta": recent_meta,
        # Static role/importance text for the dashboard
        "algo_roles": [
            {
                "name": "Kyber (KEM)",
                "role": "Securely exchanges the session key (post-quantum).",
                "importance": "Prevents future decryption (harvest-now, decrypt-later).",
                "hacker": "Must solve lattice MLWE → currently infeasible even with quantum."
            },
            {
                "name": "Dilithium (Signature)",
                "role": "Proves sender authenticity; prevents forgery (post-quantum).",
                "importance": "Long-term authenticity of software/messages.",
                "hacker": "Forge lattice signature → infeasible with current knowledge."
            },
            {
                "name": "AES-GCM",
                "role": "Fast symmetric encryption; integrity via AEAD tag.",
                "importance": "Protects bulk data in motion and at rest.",
                "hacker": "Brute-force 2^256 (impossible); pitfalls: key/nonce reuse, side-channels."
            },
            {
                "name": "ChaCha20-Poly1305",
                "role": "Stream cipher + MAC, constant-time; great on mobile CPUs.",
                "importance": "Performance + side-channel resistance.",
                "hacker": "Brute-force key only; constant-time design thwarts timing attacks."
            },
            {
                "name": "SHA3-256",
                "role": "Integrity hash; input to signatures.",
                "importance": "Detects any tampering reliably.",
                "hacker": "Collisions/preimages computationally infeasible (e.g., 2^128 for collisions)."
            },
            {
                "name": "ECC/Ed25519 (fallback)",
                "role": "Fast classical signatures where PQ not available.",
                "importance": "Widely deployed; easy integration.",
                "hacker": "ECDLP hard on classical; vulnerable to quantum (Shor) in the future."
            },
            {
                "name": "RSA (legacy)",
                "role": "Classical signatures/encryption; legacy compatibility.",
                "importance": "Interoperability with older systems.",
                "hacker": "Factoring n; strong today at ≥2048 bits, broken by future quantum."
            }
        ],
        "meta_explain": [
            {"key": "pq_kem", "meaning": "True if post-quantum KEM (Kyber) was used; False means classical fallback/simulation."},
            {"key": "pq_sign", "meaning": "True if post-quantum signature (Dilithium) was used; False means Ed25519/RSA."},
            {"key": "sym_algo", "meaning": "Symmetric cipher used to encrypt the message payload (AES or CHACHA20)."},
            {"key": "kem_ct", "meaning": "KEM ciphertext sent to the receiver so they can derive the same session key."},
            {"key": "nonce", "meaning": "Unique per-message number for AEAD; never reuse with the same key."},
            {"key": "ciphertext", "meaning": "The encrypted message bytes; looks like random data."},
            {"key": "hash_hex", "meaning": "SHA3-256 digest of plaintext; used for signing and integrity checks."},
            {"key": "signature", "meaning": "Digital signature over hash; proves the sender and prevents forgery."},
            {"key": "signer_pk", "meaning": "Public key needed to verify the signature (included for self-contained verification)."},
            {"key": "ss", "meaning": "Shared secret (DEMO ONLY). Do NOT store in production systems."},
        ],
    }
    return render(request, "dashboard/dashboard.html", context)


def about(request):
    return render(request, 'about/about.html')

# chat
# myapp/views.py

from django.db.models import Q, Exists, OuterRef
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages

from .models import CustomUser, Message
from .crypto_utils import (
    secure_send_plaintext,
    secure_receive_message,
    kem_generate,
    generate_sign_keypair,
    derive_sym_key,
    decrypt_aes_gcm,
    decrypt_chacha20,
    CryptoConfigError,
)

# =========================================================
# USER LIST WITH UNREAD INDICATOR
# =========================================================

@login_required
def user_list_view(request):
    query = request.GET.get('q', '')
    User = get_user_model()

    users = User.objects.exclude(id=request.user.id)

    if query:
        users = users.filter(
            Q(username__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(email__icontains=query)
        )

    unread_exists = Message.objects.filter(
        sender=OuterRef('pk'),
        receiver=request.user,
        is_read=False
    )

    users = users.annotate(has_unread=Exists(unread_exists))

    return render(request, 'users/user_list.html', {
        'users': users,
        'query': query,
    })


# =========================================================
# CRYPTO HELPERS
# =========================================================

def _ensure_user_keys(user: CustomUser):
    """Ensure user has KEM + signature keypairs."""
    changed = False

    if not user.kem_pk or not user.kem_sk:
        kem = kem_generate()
        user.kem_pk = kem["pk"]
        user.kem_sk = kem["sk"]
        changed = True

    if not user.sign_pk or not user.sign_sk:
        sig = generate_sign_keypair()
        user.sign_pk = sig["pk"]
        user.sign_sk = sig["sk"]
        changed = True

    if changed:
        user.save(update_fields=["kem_pk", "kem_sk", "sign_pk", "sign_sk"])


def _decrypt_self_sent(meta: dict) -> str:
    """
    DEMO ONLY.
    Allows sender to decrypt their own message using stored shared secret.
    REMOVE in production.
    """
    if not meta:
        return "(unable to decrypt)"

    ss_b64 = meta.get("ss")
    if not ss_b64:
        return "(sent – encrypted)"

    key = derive_sym_key(ss_b64)
    algo = (meta.get("sym_algo") or "AES").upper()

    if algo == "AES":
        pt = decrypt_aes_gcm(meta["nonce"], meta["ciphertext"], key)
    elif algo == "CHACHA20":
        pt = decrypt_chacha20(meta["nonce"], meta["ciphertext"], key)
    else:
        return "(unknown cipher)"

    return pt.decode("utf-8", errors="replace")


# =========================================================
# CHAT VIEW (TEXT + IMAGE + AUDIO + VIDEO)
# =========================================================

@login_required
def chat_view_by_id(request, user_id):
    other_user = get_object_or_404(CustomUser, id=user_id)

    # Ensure crypto keys exist
    _ensure_user_keys(request.user)
    _ensure_user_keys(other_user)

    # Fetch conversation (latest first)
    qs = Message.objects.filter(
        Q(sender=request.user, receiver=other_user) |
        Q(sender=other_user, receiver=request.user)
    ).order_by('-timestamp')

    # Mark unread messages as read
    Message.objects.filter(
        sender=other_user,
        receiver=request.user,
        is_read=False,
        is_group_message=False
    ).update(is_read=True)

    # -----------------------------------------------------
    # SEND MESSAGE
    # -----------------------------------------------------
    if request.method == "POST":
        text = (request.POST.get("text") or "").strip()
        image = request.FILES.get("image")
        audio = request.FILES.get("audio")
        video = request.FILES.get("video")
        sym_algo = (request.POST.get("sym_algo") or "AES").upper()

        if text or image or audio or video:
            try:
                meta = None
                if text:
                    meta = secure_send_plaintext(
                        plaintext=text,
                        recipient_kem_pk_b64=other_user.kem_pk,
                        sender_sign_sk_b64=request.user.sign_sk,
                        sender_sign_pk_b64=request.user.sign_pk,
                        use_pq_sign=True,
                        sym_algo=sym_algo,
                    )

                Message.objects.create(
                    sender=request.user,
                    receiver=other_user,
                    text="",
                    encrypted_meta=meta,
                    image=image,
                    audio=audio,
                    video=video,
                    is_group_message=False,
                )

            except CryptoConfigError as e:
                messages.error(request, f"Crypto error: {e}")
            except Exception as e:
                messages.error(request, f"Send failed: {e}")

        return redirect("chat", user_id=other_user.id)

    # -----------------------------------------------------
    # DISPLAY MESSAGES
    # -----------------------------------------------------
    display_items = []

    for msg in qs:
        meta = msg.encrypted_meta or {}

        entry = {
            "timestamp": msg.timestamp,
            "from": msg.sender,
            "meta": meta,
            "image": msg.image,
            "audio": msg.audio,
            "video": msg.video,
        }

        try:
            if msg.sender == request.user:
                entry["plaintext"] = _decrypt_self_sent(meta)
                entry["signature_valid"] = None
            else:
                fallback_pk = msg.sender.sign_pk
                plaintext, sig_ok = secure_receive_message(
                    recipient_kem_sk_b64=request.user.kem_sk,
                    stored_meta=meta,
                    fallback_signer_pk_b64=fallback_pk,
                )
                entry["plaintext"] = plaintext
                entry["signature_valid"] = sig_ok

        except Exception as e:
            entry["plaintext"] = "(decryption : ynytcdtr547886vrtcxsew)"
            entry["signature_valid"] = False
            entry["decrypt_error"] = str(e)

        display_items.append(entry)

    return render(request, "users/chat.html", {
        "messages": display_items,
        "receiver": other_user,
    })


# Feedback

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .forms import FeedbackForm
from .models import Feedback

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .models import Feedback
from .forms import FeedbackForm  # Make sure this form uses 'message' field
from django.contrib import messages

@login_required
def feedback_view(request):
    if request.method == 'POST':
        # Create form manually since the HTML form doesn't use Django's form rendering
        message = request.POST.get('text')  # textarea name is 'text'
        if message:
            Feedback.objects.create(user=request.user, message=message)
            return redirect('feedback')  # redirect to avoid resubmission
        else:
            messages.error(request, "Feedback message cannot be empty.")
    
    # Get user's past feedback
    feedbacks = Feedback.objects.filter(user=request.user).order_by('created_at')
    
    return render(request, 'feedback/feedback.html', {
        'feedbacks': feedbacks
    })


@login_required
def view_feedbacks(request):
    if request.user.is_superuser:
        feedbacks = Feedback.objects.all().order_by('-created_at')
        return render(request, 'feedback/view_feedbacks.html', {'feedbacks': feedbacks})
    else:
        return redirect('dashboard')

# myapp/views.py
# myapp/views.py

# views.py
# myapp/views.py
