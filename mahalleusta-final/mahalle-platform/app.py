import os
from flask import Flask
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from models import db, User

load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Config
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'mahalle-hizmet-super-secret-key-2024')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///mahalle_hizmet.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
    app.config['WTF_CSRF_TIME_LIMIT'] = None
    
    # Extensions
    db.init_app(app)
    bcrypt = Bcrypt(app)
    csrf = CSRFProtect(app)
    
    login_manager = LoginManager(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Bu sayfaya erişmek için giriş yapmalısınız.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from routes import auth_bp, main_bp, provider_bp, admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(provider_bp)
    app.register_blueprint(admin_bp)

    # Create tables and default admin
    with app.app_context():
        db.create_all()
        _create_default_admin(bcrypt)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    return app


def _create_default_admin(bcrypt):
    from models import User
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(username='admin', email='admin@mahalle.com', password_hash=pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("✅ Varsayılan admin oluşturuldu: admin / admin123")


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
