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
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from django.db.models import Exists, OuterRef

@login_required
def user_list_view(request):
    query = request.GET.get('q', '')
    User = get_user_model()
    users = User.objects.exclude(id=request.user.id)

    # Filter by query if present
    if query:
        users = users.filter(
            Q(username__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(email__icontains=query)
        )

    # Annotate users with 'has_unread' flag
    from .models import Message
    unread_exists = Message.objects.filter(
        sender=OuterRef('pk'),
        receiver=request.user,
        is_read=False
    )
    users = users.annotate(has_unread=Exists(unread_exists))

    context = {
        'users': users,
        'query': query,
    }
    return render(request, 'users/user_list.html', context)


# @login_required
# def chat_view_by_id(request, user_id):
#     other_user = get_object_or_404(CustomUser, id=user_id)
#     messages = Message.objects.filter(
#         (Q(sender=request.user) & Q(receiver=other_user)) |
#         (Q(sender=other_user) & Q(receiver=request.user))
#     ).order_by('timestamp')

#     if request.method == 'POST':
#         text = request.POST.get('text')
#         image = request.FILES.get('image')
#         Message.objects.create(sender=request.user, receiver=other_user, text=text, image=image)
#         return redirect('chat', user_id=other_user.id)  # ✅ Corrected: use user_id instead of username

#     return render(request, 'users/chat.html', {
#         'messages': messages,
#         'receiver': other_user
#     })

# users/views.py (replace existing chat_view_by_id)
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from .models import CustomUser, Message
from .crypto_utils import secure_send_plaintext, secure_receive_message, sha3_256_hex
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q
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

def _ensure_user_keys(user: CustomUser):
    """Ensure each user has Kyber + Signature keypairs."""
    changed = False
    if not getattr(user, "kem_pk", None) or not getattr(user, "kem_sk", None):
        kem = kem_generate()
        user.kem_pk, user.kem_sk = kem["pk"], kem["sk"]
        changed = True
    if not getattr(user, "sign_pk", None) or not getattr(user, "sign_sk", None):
        sig = generate_sign_keypair()
        user.sign_pk, user.sign_sk = sig["pk"], sig["sk"]
        changed = True
    if changed:
        user.save()

def _decrypt_self_sent(meta: dict) -> str:
    """Demo-only: decrypt message sent by me using stored shared secret `ss`."""
    if not meta:
        return "(unable to decrypt)"
    ss_b64 = meta.get("ss")
    if not ss_b64:
        return "(sent – encrypted stored)"
    key = derive_sym_key(ss_b64)
    algo = (meta.get("sym_algo") or "AES").upper()
    if algo == "AES":
        pt = decrypt_aes_gcm(meta["nonce"], meta["ciphertext"], key)
    elif algo == "CHACHA20":
        pt = decrypt_chacha20(meta["nonce"], meta["ciphertext"], key)
    else:
        return "(unknown cipher)"
    return pt.decode("utf-8", errors="replace")



@login_required
def chat_view_by_id(request, user_id):
    other_user = get_object_or_404(CustomUser, id=user_id)

    # Ensure both users have valid crypto keys
    _ensure_user_keys(request.user)
    _ensure_user_keys(other_user)

    # Fetch conversation — latest first
    qs = Message.objects.filter(
        (Q(sender=request.user) & Q(receiver=other_user)) |
        (Q(sender=other_user) & Q(receiver=request.user))
    ).order_by('-timestamp')  # ✅ Newest messages appear at top

    # ✅ Mark all unread messages from THEM to YOU as read
    Message.objects.filter(
        sender=other_user,
        receiver=request.user,
        is_read=False,
        is_group_message=False,  # keep if you want to ignore group messages
    ).update(is_read=True)

    # Handle sending a new message
    if request.method == 'POST':
        text = (request.POST.get('text') or '').strip()
        if text:
            sym_algo = (request.POST.get('sym_algo') or 'AES').upper()
            try:
                meta = secure_send_plaintext(
                    plaintext=text,
                    recipient_kem_pk_b64=other_user.kem_pk,
                    sender_sign_sk_b64=request.user.sign_sk,
                    sender_sign_pk_b64=request.user.sign_pk,
                    use_pq_sign=True,
                    sym_algo=sym_algo
                )
                Message.objects.create(
                    sender=request.user,
                    receiver=other_user,
                    text='',
                    encrypted_meta=meta,
                    is_group_message=False,  # explicit if you use this flag
                )
            except CryptoConfigError as e:
                messages.error(request, f"Crypto configuration error: {e}")
            except Exception as e:
                messages.error(request, f"Unexpected crypto error: {e}")
        return redirect('chat', user_id=other_user.id)

    # Display messages (decrypt for receiver & self)
    display_items = []
    for msg in qs:
        meta = msg.encrypted_meta or {}
        entry = {
            'timestamp': msg.timestamp,
            'from': msg.sender,
            'meta': meta,
            'image': getattr(msg, "image", None),
        }
        try:
            if msg.sender == request.user:
                # decrypt own message using stored shared secret (demo only)
                entry['plaintext'] = _decrypt_self_sent(meta)
                entry['signature_valid'] = None
            else:
                fallback_pk = msg.sender.sign_pk if getattr(msg.sender, "sign_pk", None) else None
                plaintext, sig_ok = secure_receive_message(
                    recipient_kem_sk_b64=request.user.kem_sk,
                    stored_meta=meta,
                    fallback_signer_pk_b64=fallback_pk
                )
                entry['plaintext'] = plaintext
                entry['signature_valid'] = sig_ok
        except Exception as e:
            entry['plaintext'] = "(decryption failed)"
            entry['signature_valid'] = False
            entry['decrypt_error'] = str(e)

        display_items.append(entry)

    return render(request, 'users/chat.html', {
        'messages': display_items,
        'receiver': other_user,
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
