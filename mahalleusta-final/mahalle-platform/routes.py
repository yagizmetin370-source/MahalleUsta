import os
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify, abort
from flask_login import login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from sqlalchemy import func
from models import db, User, ServiceProvider, Review
from functools import wraps
from PIL import Image

auth_bp = Blueprint('auth', __name__)
main_bp = Blueprint('main', __name__)
provider_bp = Blueprint('provider', __name__)
admin_bp = Blueprint('admin', __name__)

bcrypt = Bcrypt()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

CATEGORIES = [
    ('elektrikci', '⚡ Elektrikçi'),
    ('tesisatci', '🔧 Tesisatçı'),
    ('boyaci', '🎨 Boyacı'),
    ('marangoz', '🪚 Marangoz'),
    ('tamirci', '🔨 Tamirci'),
    ('ozel_ders', '📚 Özel Ders'),
    ('bilgisayarci', '💻 Bilgisayarcı'),
    ('temizlik', '🧹 Temizlik'),
    ('tasima', '🚛 Taşımacılık'),
    ('bahce', '🌿 Bahçe Bakımı'),
    ('klima', '❄️ Klima Servisi'),
    ('cicekci', '🌸 Çiçekçi'),
    ('fotoğrafci', '📷 Fotoğrafçı'),
    ('diger', '🔵 Diğer'),
]

CITIES = {
    'Ankara': {
        'Çankaya': ['Kızılay', 'Bahçelievler', 'Birlik', 'Emek', 'Öveçler', 'Dikmen', 'Çukurambar'],
        'Keçiören': ['Etlik', 'Bağlum', 'Kalaba', 'Şaşmaz', 'Aktepe'],
        'Mamak': ['Karapürçek', 'Tuzluçayır', 'Dutluk', 'Hüseyin Gazi'],
        'Sincan': ['Fatih', 'Şehit Osman Avcı', 'Gökçekent'],
        'Etimesgut': ['Elvankent', 'Eryaman', 'Bağlıca'],
    },
    'İstanbul': {
        'Kadıköy': ['Moda', 'Fenerbahçe', 'Bostancı', 'Göztepe', 'Kozyatağı'],
        'Beşiktaş': ['Levent', 'Etiler', 'Bebek', 'Arnavutköy'],
        'Üsküdar': ['Bağlarbaşı', 'Çengelköy', 'Beylerbeyi', 'Kuzguncuk'],
        'Şişli': ['Nişantaşı', 'Mecidiyeköy', 'Bomonti', 'Feriköy'],
        'Beyoğlu': ['Cihangir', 'Galata', 'Tarlabaşı', 'Kasımpaşa'],
    },
    'İzmir': {
        'Konak': ['Alsancak', 'Güzelyalı', 'Hatay', 'Üçyol'],
        'Karşıyaka': ['Bostanlı', 'Tersane', 'Donanmacı'],
        'Bornova': ['Mevlana', 'Erzene', 'Işıkkent'],
    }
}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_photo(file):
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    img = Image.open(file)
    img.thumbnail((400, 400))
    img.save(filepath)
    return filename


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ─── MAIN ROUTES ───────────────────────────────────────────────────────────────

@main_bp.route('/')
def index():
    featured = ServiceProvider.query.filter_by(is_approved=True).order_by(
        func.random()).limit(6).all()
    total_providers = ServiceProvider.query.filter_by(is_approved=True).count()
    total_users = User.query.count()
    return render_template('index.html',
                           featured=featured,
                           categories=CATEGORIES,
                           cities=CITIES,
                           total_providers=total_providers,
                           total_users=total_users)


@main_bp.route('/search')
def search():
    category = request.args.get('category', '')
    city = request.args.get('city', '')
    district = request.args.get('district', '')
    neighborhood = request.args.get('neighborhood', '')
    q = request.args.get('q', '')

    query = ServiceProvider.query.filter_by(is_approved=True)

    if category:
        query = query.filter(ServiceProvider.category == category)
    if city:
        query = query.filter(ServiceProvider.city == city)
    if district:
        query = query.filter(ServiceProvider.district == district)
    if neighborhood:
        query = query.filter(ServiceProvider.neighborhood == neighborhood)
    if q:
        query = query.filter(ServiceProvider.full_name.ilike(f'%{q}%'))

    providers = query.all()
    return render_template('search.html',
                           providers=providers,
                           categories=CATEGORIES,
                           cities=CITIES,
                           selected_category=category,
                           selected_city=city,
                           selected_district=district,
                           selected_neighborhood=neighborhood,
                           q=q)


@main_bp.route('/provider/<int:provider_id>')
def provider_detail(provider_id):
    provider = ServiceProvider.query.get_or_404(provider_id)
    if not provider.is_approved and not (current_user.is_authenticated and current_user.is_admin):
        abort(404)
    user_reviewed = False
    if current_user.is_authenticated:
        user_reviewed = Review.query.filter_by(
            provider_id=provider_id, user_id=current_user.id).first() is not None
    return render_template('provider_detail.html', provider=provider,
                           categories=dict(CATEGORIES), user_reviewed=user_reviewed)


@main_bp.route('/provider/<int:provider_id>/review', methods=['POST'])
@login_required
def add_review(provider_id):
    provider = ServiceProvider.query.get_or_404(provider_id)
    existing = Review.query.filter_by(provider_id=provider_id, user_id=current_user.id).first()
    if existing:
        flash('Bu hizmet veren için zaten yorum yaptınız.', 'warning')
        return redirect(url_for('main.provider_detail', provider_id=provider_id))

    rating = request.form.get('rating', type=int)
    comment = request.form.get('comment', '').strip()

    if not rating or rating < 1 or rating > 5:
        flash('Geçerli bir puan seçiniz.', 'danger')
        return redirect(url_for('main.provider_detail', provider_id=provider_id))

    review = Review(provider_id=provider_id, user_id=current_user.id,
                    rating=rating, comment=comment)
    db.session.add(review)
    db.session.commit()
    flash('Yorumunuz eklendi! Teşekkürler.', 'success')
    return redirect(url_for('main.provider_detail', provider_id=provider_id))


@main_bp.route('/api/districts')
def get_districts():
    city = request.args.get('city', '')
    districts = list(CITIES.get(city, {}).keys())
    return jsonify(districts)


@main_bp.route('/api/neighborhoods')
def get_neighborhoods():
    city = request.args.get('city', '')
    district = request.args.get('district', '')
    neighborhoods = CITIES.get(city, {}).get(district, [])
    return jsonify(neighborhoods)


# ─── AUTH ROUTES ───────────────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not all([username, email, password, confirm]):
            flash('Tüm alanları doldurunuz.', 'danger')
            return render_template('register.html')

        if password != confirm:
            flash('Şifreler eşleşmiyor.', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Şifre en az 6 karakter olmalı.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Bu e-posta zaten kayıtlı.', 'danger')
            return render_template('register.html')

        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()
        flash('Kayıt başarılı! Giriş yapabilirsiniz.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Hesabınız askıya alınmış.', 'danger')
                return render_template('login.html')
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash(f'Hoş geldiniz, {user.username}!', 'success')
            return redirect(next_page or url_for('main.index'))
        flash('E-posta veya şifre hatalı.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Çıkış yapıldı.', 'info')
    return redirect(url_for('main.index'))


# ─── PROVIDER ROUTES ───────────────────────────────────────────────────────────

@provider_bp.route('/become-provider', methods=['GET', 'POST'])
@login_required
def become_provider():
    if current_user.provider:
        flash('Zaten hizmet veren profiliniz var.', 'info')
        return redirect(url_for('provider.dashboard'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        category = request.form.get('category', '')
        phone = request.form.get('phone', '').strip()
        description = request.form.get('description', '').strip()
        city = request.form.get('city', '')
        district = request.form.get('district', '')
        neighborhood = request.form.get('neighborhood', '')

        if not all([full_name, category, phone, city, district, neighborhood]):
            flash('Zorunlu alanları doldurunuz.', 'danger')
            return render_template('become_provider.html', categories=CATEGORIES, cities=CITIES)

        photo_filename = 'default.png'
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename and allowed_file(file.filename):
                photo_filename = save_photo(file)

        provider = ServiceProvider(
            user_id=current_user.id,
            full_name=full_name,
            category=category,
            phone=phone,
            description=description,
            city=city,
            district=district,
            neighborhood=neighborhood,
            profile_photo=photo_filename
        )
        db.session.add(provider)
        db.session.commit()
        flash('Profiliniz oluşturuldu! Admin onayı bekleniyor.', 'success')
        return redirect(url_for('provider.dashboard'))

    return render_template('become_provider.html', categories=CATEGORIES, cities=CITIES)


@provider_bp.route('/dashboard')
@login_required
def dashboard():
    if not current_user.provider:
        flash('Önce hizmet veren profili oluşturmalısınız.', 'warning')
        return redirect(url_for('provider.become_provider'))
    provider = current_user.provider
    recent_reviews = Review.query.filter_by(provider_id=provider.id)\
        .order_by(Review.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', provider=provider,
                           categories=dict(CATEGORIES), recent_reviews=recent_reviews)


@provider_bp.route('/dashboard/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if not current_user.provider:
        return redirect(url_for('provider.become_provider'))
    provider = current_user.provider

    if request.method == 'POST':
        provider.full_name = request.form.get('full_name', provider.full_name).strip()
        provider.category = request.form.get('category', provider.category)
        provider.phone = request.form.get('phone', provider.phone).strip()
        provider.description = request.form.get('description', '').strip()
        provider.city = request.form.get('city', provider.city)
        provider.district = request.form.get('district', provider.district)
        provider.neighborhood = request.form.get('neighborhood', provider.neighborhood)

        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename and allowed_file(file.filename):
                provider.profile_photo = save_photo(file)

        db.session.commit()
        flash('Profiliniz güncellendi.', 'success')
        return redirect(url_for('provider.dashboard'))

    return render_template('edit_profile.html', provider=provider,
                           categories=CATEGORIES, cities=CITIES)


# ─── ADMIN ROUTES ──────────────────────────────────────────────────────────────

@admin_bp.route('/admin')
@login_required
@admin_required
def admin_index():
    total_users = User.query.count()
    total_providers = ServiceProvider.query.count()
    pending = ServiceProvider.query.filter_by(is_approved=False).count()
    total_reviews = Review.query.count()
    return render_template('admin/index.html',
                           total_users=total_users,
                           total_providers=total_providers,
                           pending=pending,
                           total_reviews=total_reviews)


@admin_bp.route('/admin/providers')
@login_required
@admin_required
def admin_providers():
    providers = ServiceProvider.query.order_by(ServiceProvider.created_at.desc()).all()
    return render_template('admin/providers.html', providers=providers,
                           categories=dict(CATEGORIES))


@admin_bp.route('/admin/providers/<int:pid>/approve', methods=['POST'])
@login_required
@admin_required
def approve_provider(pid):
    provider = ServiceProvider.query.get_or_404(pid)
    provider.is_approved = True
    db.session.commit()
    flash(f'{provider.full_name} onaylandı.', 'success')
    return redirect(url_for('admin.admin_providers'))


@admin_bp.route('/admin/providers/<int:pid>/verify', methods=['POST'])
@login_required
@admin_required
def verify_provider(pid):
    provider = ServiceProvider.query.get_or_404(pid)
    provider.is_verified = not provider.is_verified
    db.session.commit()
    status = 'doğrulandı' if provider.is_verified else 'doğrulama kaldırıldı'
    flash(f'{provider.full_name} {status}.', 'success')
    return redirect(url_for('admin.admin_providers'))


@admin_bp.route('/admin/providers/<int:pid>/delete', methods=['POST'])
@login_required
@admin_required
def delete_provider(pid):
    provider = ServiceProvider.query.get_or_404(pid)
    db.session.delete(provider)
    db.session.commit()
    flash('Hizmet veren silindi.', 'success')
    return redirect(url_for('admin.admin_providers'))


@admin_bp.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@admin_bp.route('/admin/users/<int:uid>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(uid):
    user = User.query.get_or_404(uid)
    if user.id == current_user.id:
        flash('Kendinizi devre dışı bırakamazsınız.', 'danger')
        return redirect(url_for('admin.admin_users'))
    user.is_active = not user.is_active
    db.session.commit()
    status = 'aktif' if user.is_active else 'askıya alındı'
    flash(f'{user.username} {status}.', 'success')
    return redirect(url_for('admin.admin_users'))


@admin_bp.route('/admin/reviews')
@login_required
@admin_required
def admin_reviews():
    reviews = Review.query.order_by(Review.created_at.desc()).all()
    return render_template('admin/reviews.html', reviews=reviews)


@admin_bp.route('/admin/reviews/<int:rid>/delete', methods=['POST'])
@login_required
@admin_required
def delete_review(rid):
    review = Review.query.get_or_404(rid)
    db.session.delete(review)
    db.session.commit()
    flash('Yorum silindi.', 'success')
    return redirect(url_for('admin.admin_reviews'))
