import os
from flask import Flask, send_from_directory,render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
import datetime
from werkzeug.exceptions import Forbidden
from functools import wraps
import logging
from cryptography.fernet import Fernet
import pyotp
import io
import qrcode
from flask_mail import Mail, Message
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from sqlalchemy import func, and_, exists
from wtforms import TextAreaField, SelectMultipleField, SubmitField
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask import request, jsonify, render_template, abort
from flask_login import login_user, current_user
from werkzeug.security import check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///azure_sim.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'sirinefakhfakh03@gmail.com'
app.config['MAIL_PASSWORD'] = 'pagz stqw fmwu ntrk'
mail = Mail(app)
app.config['RECAPTCHA_PUBLIC_KEY'] = 'your_public_key'
app.config['RECAPTCHA_PRIVATE_KEY'] = 'your_private_key'
logging.basicConfig(
    filename='security_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    totp_secret = db.Column(db.String(120), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)
    role_relation = db.relationship('Role', backref='users', foreign_keys=[role_id])
    is_active = db.Column(db.Boolean, default=True)  

    def has_permission(self, permission_name):
        if not self.role_relation:
            return False
        return db.session.query(
            exists().where(
                and_(
                    RolePermission.role_id == self.role_relation.id,
                    RolePermission.permission_id == Permission.id,
                    Permission.name == permission_name
                )
            )
        ).scalar()

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    value = db.Column(db.Text, nullable=False)  # Encrypted file content or secret
    key = db.Column(db.Text, nullable=False)  # Encrypted encryption key
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))
    
    user = db.relationship('User', backref='activities')
class FirewallRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(100), nullable=False)

class SecurityAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Unresolved') 
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Recommendation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), nullable=False)

class ComplianceStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    control = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    s_system_role = db.Column(db.Boolean, default=False)
    role_permissions = db.relationship('RolePermission', back_populates='role', cascade='all, delete-orphan')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    role_permissions = db.relationship('RolePermission', back_populates='permission')

class RolePermission(db.Model):
    __tablename__ = 'role_permission'
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'))
    permission = db.relationship('Permission', back_populates='role_permissions')
    role = db.relationship('Role', back_populates='role_permissions')
    
from datetime import datetime, timedelta
@app.route('/thread_protection', methods=['GET', 'POST'])
def thread_protection():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Unauthorized'}), 401

    if request.method == 'POST':
        data = request.get_json()
        level = data.get('protectionLevel')
        return jsonify({'success': f'Thread protection set to {level}'}), 200

    return render_template('thread_protection.html')

def verify_permissions():
    with app.app_context():
        roles = Role.query.all()
        permissions = Permission.query.all()
        for role in roles:
            for permission in permissions:
                existing_assoc = RolePermission.query.filter_by(role_id=role.id, permission_id=permission.id).first()
                if not existing_assoc:
                    print(f"Permission '{permission.name}' is not assigned to role '{role.name}'")



fernet_cipher = Fernet(Fernet.generate_key())

def generate_key_from_password(password, salt, algorithm='scrypt'):
    if algorithm == 'scrypt':
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    else:
        raise ValueError("Unsupported algorithm")

def caesar_cipher_encrypt(text, shift):
    encrypted = []
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def aes_encrypt(data, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def aes_decrypt(encrypted_data, key):
    backend = default_backend()
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    if not current_user.has_permission('encrypt'):
        return render_template('error.html')  # Redirigez vers la page d'accueil ou une autre page

    if request.method == 'POST':
        data = request.form['data']
        encryption_type = request.form['encryption_type']
        password = request.form.get('password', None)

        if encryption_type == 'fernet':
            encrypted_data = fernet_cipher.encrypt(data.encode()).decode()
        elif encryption_type == 'scrypt':
            if not password:
                return jsonify({'error': 'Password is required for key derivation encryption'}), 400
            salt = os.urandom(16)
            key = generate_key_from_password(password, salt)
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(data.encode()).decode()
        elif encryption_type == 'caesar':
            shift = int(request.form.get('shift', 3))  # Default shift of 3
            encrypted_data = caesar_cipher_encrypt(data, shift)
        elif encryption_type == 'aes':
            if not password:
                return jsonify({'error': 'Password is required for AES encryption'}), 400
            key = password.encode().ljust(32)[:32]
            encrypted_data = aes_encrypt(data, key)
        else:
            return jsonify({'error': 'Unsupported encryption type'}), 400

        return jsonify({'encrypted_data': encrypted_data})

    return render_template('encrypt.html')


@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    if not current_user.has_permission('encrypt'):
        return render_template('error.html')  # Redirigez vers la page d'accueil ou une autre page

    
    
    encrypted_data = request.form['encrypted_data']
    decryption_type = request.form['decryption_type']
    password = request.form.get('decrypt_password', None)

    try:
        if decryption_type == 'fernet':
            decrypted_data = fernet_cipher.decrypt(encrypted_data.encode()).decode()
        elif decryption_type in ['scrypt']:
            if not password:
                return jsonify({'error': 'Password is required for key derivation decryption'}), 400
            salt = os.urandom(16)  # This must match the encryption salt for production.
            key = generate_key_from_password(password, salt)
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()
        elif decryption_type == 'caesar':
            shift = int(request.form.get('shift', -3))  # Reversing shift by default
            decrypted_data = caesar_cipher_encrypt(encrypted_data, shift)
        elif decryption_type == 'aes':
            if not password:
                return jsonify({'error': 'Password is required for AES decryption'}), 400
            key = password.encode().ljust(32)[:32]
            decrypted_data = aes_decrypt(encrypted_data, key)
        else:
            return jsonify({'error': 'Unsupported decryption type'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'decrypted_data': decrypted_data})
def check_user_permissions(username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"User role: {user.role}")
            print(f"User role relation: {user.role_relation}")
            has_encrypt = user.has_permission('encrypt')
            print(f"Has encrypt permission: {has_encrypt}")


@app.route('/manage_roles')
@login_required
def manage_roles():
    roles = db.session.query(Role).options(
        joinedload(Role.role_permissions).joinedload(RolePermission.permission)
    ).all()
    return render_template('admin/manage_roles.html', roles=roles)

class CreateRoleForm(FlaskForm):
    name = StringField('Role Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Create Role')

class EditRoleForm(FlaskForm):
    name = StringField('Role Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Update Role')
class DeleteRoleForm(FlaskForm):
    submit = SubmitField('Delete Role')
admin_bp = Blueprint('admin_bp', __name__)
@admin_bp.route('/edit_role/<int:role_id>', methods=['GET', 'POST'])
@login_required
def edit_role(role_id):
    role = Role.query.get_or_404(role_id)
    form = EditRoleForm(obj=role)

    if form.validate_on_submit():
        try:
            form.populate_obj(role)
            db.session.commit()
            flash('Role updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating role: {e}', 'danger')
        return redirect(url_for('admin_bp.manage_roles'))
    
    return render_template('edit_role.html', form=form, role=role)



@admin_bp.route('manage_roles', methods=['GET'])
@login_required
def manage_roles():
    
    
    roles = Role.query.all()
    return render_template('admin/manage_roles.html', roles=roles)


@admin_bp.route('/create_role', methods=['GET', 'POST'])
@login_required
def create_role():
    if current_user.role != 'admin':
        flash('Access denied. Admin rights required.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        role_name = request.form.get('name')
        role_description = request.form.get('description')
        permissions = request.form.getlist('permissions')
       
        
        # Vérifiez si le rôle existe déjà
        existing_role = Role.query.filter_by(name=role_name).first()
        if existing_role:
            flash('Role name already exists', 'danger')
            return redirect(url_for('admin_bp.create_role'))
        
        new_role = Role(name=role_name, description=role_description)
        db.session.add(new_role)
        db.session.commit()
        
        # Ajoutez les permissions au rôle
        for permission_name in permissions:
            permission = Permission.query.filter_by(name=permission_name).first()
            if permission:
                role_permission = RolePermission(role_id=new_role.id, permission_id=permission.id)
                db.session.add(role_permission)
        
        db.session.commit()
        flash('Role created successfully', 'success')
        return redirect(url_for('admin_bp.manage_roles'))
    
    permissions = Permission.query.all()
    return render_template('admin/create_role.html', permissions=permissions)


from sqlalchemy.orm import joinedload

@admin_bp.route('/delete_role/<int:role_id>', methods=['POST'])
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    db.session.delete(role)
    db.session.commit()
    flash('Role deleted successfully', 'success')
    return redirect(url_for('admin_bp.manage_roles'))

@admin_bp.route('/assign_role/<int:user_id>', methods=['GET', 'POST'])
@login_required
def assign_role(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()
    
    if request.method == 'POST':
        role_id = request.form.get('role_id')
        if role_id:
            role = Role.query.get(role_id)
            if role:
            # Retrieve all Permission objects linked to the role
                permissions = [rp.permission for rp in role.role_permissions]
                print(f"Permissions for role {role.name}: {[perm.name for perm in permissions]}")

                flash('Role assigned successfully', 'success')
                return redirect(url_for('admin_bp.manage_users'))
        flash('Invalid role selected', 'danger')
    
    return render_template('admin/assign_role.html', user=user, roles=roles)

@app.route('/create_alert', methods=['POST'])
def create_alert():
    data = request.get_json()
    message = data.get('message')
    
    if not message:
        return jsonify({'success': False, 'error': 'Message is required'}), 400
    
    try:
        msg = Message("Security Alert", sender="sirinefakhfakh03@gmail.com", recipients=["sirinefakhfakh03@gmail.com"])
        msg.body = message
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/asc_dashboard')
@login_required
def asc_dashboard():
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # More sophisticated query handling
    alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    recommendations = Recommendation.query.order_by(Recommendation.id.desc()).paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    compliance_statuses = ComplianceStatus.query.order_by(ComplianceStatus.id.desc()).paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    # Aggregated risk counts with dynamic calculation
    high_risk_count = SecurityAlert.query.filter_by(severity='High').count()
    medium_risk_count = SecurityAlert.query.filter_by(severity='Medium').count()
    low_risk_count = SecurityAlert.query.filter_by(severity='Low').count()
    resolved_count = SecurityAlert.query.filter_by(status='Resolved').count()

    # Trend calculations with more nuanced logic
    def calculate_trend(current_period, previous_period):
        if previous_period == 0:
            return 100 if current_period > 0 else 0  # Return 100% if there is an increase, otherwise 0%
        return round(((current_period - previous_period) / previous_period) * 100, 1)

    # Example trend calculation (replace with actual time-based logic)
    alerts_this_month = SecurityAlert.query.filter(
        SecurityAlert.timestamp >= datetime.utcnow() - timedelta(days=30)
    ).count()
    alerts_last_month = SecurityAlert.query.filter(
        SecurityAlert.timestamp >= datetime.utcnow() - timedelta(days=60),
        SecurityAlert.timestamp < datetime.utcnow() - timedelta(days=30)
    ).count()
    alerts_trend = calculate_trend(alerts_this_month, alerts_last_month)

    # Example recommendations trend calculation (replace with actual time-based logic)
    recommendations_this_month = Recommendation.query.filter(
        Recommendation.id >= datetime.utcnow() - timedelta(days=30)
    ).count()
    recommendations_last_month = Recommendation.query.filter(
        Recommendation.id >= datetime.utcnow() - timedelta(days=60),
        Recommendation.id < datetime.utcnow() - timedelta(days=30)
    ).count()
    recommendations_trend = calculate_trend(recommendations_this_month, recommendations_last_month)

    # Example compliance rate calculation (replace with actual logic)
    total_controls = ComplianceStatus.query.count()
    compliant_controls = ComplianceStatus.query.filter_by(status='Compliant').count()
    compliance_rate = round((compliant_controls / total_controls) * 100, 1) if total_controls > 0 else 0

    return render_template('asc_dashboard.html', 
                           alerts=alerts.items, 
                           recommendations=recommendations.items, 
                           compliance_statuses=compliance_statuses.items,
                           high_risk_count=high_risk_count, 
                           medium_risk_count=medium_risk_count, 
                           low_risk_count=low_risk_count, 
                           resolved_count=resolved_count,
                           alerts_trend=alerts_trend,
                           recommendations_trend=recommendations_trend,
                           compliance_rate=compliance_rate)
@app.route('/add_alert', methods=['POST'])
@login_required
def add_alert():
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    severity = data.get('severity')

    if not title or not description or not severity:
        return jsonify({'error': 'Missing required fields'}), 400
    
    alert = SecurityAlert(title=title, description=description, severity=severity)
    db.session.add(alert)
    db.session.commit()
    return jsonify({'success': 'Alert added successfully'}), 200

@app.route('/add_recommendation', methods=['POST'])
@login_required
def add_recommendation():
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    status = data.get('status')

    if not title or not description or not status:
        return jsonify({'error': 'Missing required fields'}), 400
    
    recommendation = Recommendation(title=title, description=description, status=status)
    db.session.add(recommendation)
    db.session.commit()
    return jsonify({'success': 'Recommendation added successfully'}), 200

@app.route('/add_compliance_status', methods=['POST'])
@login_required
def add_compliance_status():
    data = request.get_json()
    control = data.get('control')
    status = data.get('status')

    if not control or not status:
        return jsonify({'error': 'Missing required fields'}), 400
    
    compliance_status = ComplianceStatus(control=control, status=status)
    db.session.add(compliance_status)
    db.session.commit()
    return jsonify({'success': 'Compliance status added successfully'}), 200






def log_firewall_rule(user_id, rule, timestamp):
    # Implement the logging logic here
    app.logger.info(f"User {user_id} added firewall rule: {rule} at {timestamp}")

@app.route('/firewall_rules', methods=['GET', 'POST'])
@login_required
def firewall_rules():
    if request.method == 'POST':
        data = request.get_json()
        rule = data.get('rule', '').strip()
        
        # Enhanced validation
        if not rule:
            return jsonify({'error': 'Rule cannot be empty'}), 400
        
        if len(rule) > 100:
            return jsonify({'error': 'Rule must be 100 characters or less'}), 400
        
       
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', rule):
            return jsonify({'error': 'Invalid rule format'}), 400
        
       
        
        return jsonify({'success': f'Firewall rule added: {rule}'}), 200
    
    
    rules = ["Allow HTTP", "Deny SSH"]
    return render_template('firewall_rules.html', rules=rules)


import uuid




api_keys = {}
api_usage = {}

@app.route('/generate_api_key', methods=['POST'])
def generate_api_key():
    user_id = request.json.get('user_id')
    new_api_key = str(uuid.uuid4())
    api_keys[user_id] = new_api_key
    api_usage[new_api_key] = {'requests': 0, 'last_used': None}
    return jsonify({'api_key': new_api_key})

api_usage = {
    "valid-api-key-123": {"requests": 0, "last_used": ""}
}

@app.route('/secure_endpoint', methods=['GET'])
def secure_endpoint():
    # Get the API key from request headers
    api_key = request.headers.get('x-api-key')

    if not api_key:
        return jsonify({"error": "API key is required"}), 400  # Bad request if no API key is provided

    if api_key not in api_usage:
        return jsonify({"error": "Invalid API key"}), 401  # Unauthorized if API key is not valid

    # Update usage statistics if API key is valid
    api_usage[api_key]['requests'] += 1
    api_usage[api_key]['last_used'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Return a success message
    return jsonify({"message": "Secure data accessed!", "usage": api_usage[api_key]})

    

@app.route('/api_usage/<user_id>', methods=['GET'])
def get_api_usage(user_id):
    user_api_key = api_keys.get(user_id)
    if user_api_key and user_api_key in api_usage:
        return jsonify(api_usage[user_api_key])
    

@app.route('/api_key')
def api_key_page():
    return render_template('api_key.html')






@admin_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    total_users = User.query.count()
    active_users = User.query.filter(User.is_active == True).count()
    users = User.query.all()
    roles = Role.query.all()
    permissions = Permission.query.all()
    
    return render_template('admin/dashboard.html', 
                           total_users=total_users,
                           active_users=active_users,
                           users=users,
                           roles=roles,
                           permissions=permissions)





@admin_bp.route('/toggle_user_status', methods=['POST'])
@login_required
def toggle_user_status():
    """
    Toggle a user's active status.
    Requires appropriate permissions.
    """
    if not current_user.has_permission('deactivate_user'):
        return jsonify({
            'success': False, 
            'message': 'Insufficient permissions'
        }), 403
    
    data = request.get_json()
    user_id = data.get('user_id') 
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
            return jsonify({
                'success': False, 
                'message': 'Cannot modify own account'
            }), 400
    user.is_active = not user.is_active
    db.session.commit()
        
    return jsonify({
            'success': True, 
            'message': f'User {user.username} status updated',
            'new_status': user.is_active
        })
    
class RoleForm(FlaskForm):
    name = StringField('Role Name', 
        validators=[
            DataRequired(message="Role name is required"),
            Length(min=3, max=50, message="Role name must be between 3 and 50 characters")
        ])
    
    description = TextAreaField('Role Description', 
        validators=[
            Length(max=500, message="Description cannot exceed 500 characters")
        ])
    
    permissions = SelectMultipleField('Permissions', 
        choices=[
            # User Management
            ('create_user', 'Create User'),
            ('edit_user', 'Edit User'),
            ('delete_user', 'Delete User'),
            ('view_users', 'View Users'),
            
            # Content Management
            ('create_content', 'Create Content'),
            ('edit_content', 'Edit Content'),
            ('delete_content', 'Delete Content'),
            ('publish_content', 'Publish Content'),
            
            # Role Management
            ('create_role', 'Create Role'),
            ('edit_role', 'Edit Role'),
            ('delete_role', 'Delete Role'),
            ('assign_roles', 'Assign Roles'),
            
            # System Settings
            ('view_logs', 'View Logs'),
            ('manage_settings', 'Manage Settings'),
            ('backup_system', 'Backup System'),
            ('restore_system', 'Restore System'),
            ('encrypt','decrypt')
            
        ])
    
    submit = SubmitField('Save Role')





@admin_bp.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Access denied. Admin rights required.', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)




@admin_bp.route('/manage_users', methods=['GET'])
@login_required
def manage_users():
    users = User.query.all()  
    return render_template('admin/manage_users.html', users=users)


@admin_bp.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin rights required.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.role = request.form.get('role')
        user.username = request.form.get('username')

        new_password = request.form.get('password')
        if new_password:
            user.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_bp.manage_users'))
    
    return render_template('admin/edit_user.html', user=user)





@admin_bp.route('/user/activity/<int:user_id>')
@login_required
def user_activity(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin rights required.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    activities = UserActivity.query.filter_by(user_id=user_id)\
        .order_by(UserActivity.timestamp.desc())\
        .limit(50).all()
    
    return render_template('admin/user_activity.html', 
                           user=user, 
                           activities=activities)



@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def generate_token(user):
    token = jwt.encode({
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'])
    return token




def init_db():
    with app.app_context():
        db.create_all()
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='Administrator role')
            db.session.add(admin_role)
            db.session.commit()
        
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@gmail.com',
                password_hash=generate_password_hash('admin'),
                role='admin',
                role_relation=admin_role, 
                
            )
            db.session.add(admin_user)
            db.session.commit()


def init_permissions():
    with app.app_context():
        permissions = [
            'create_user', 'edit_user', 'delete_user', 'view_users',
            'create_content', 'edit_content', 'delete_content', 'publish_content',
            'create_role', 'edit_role', 'delete_role', 'assign_roles',
            'view_logs', 'manage_settings', 'backup_system', 'restore_system','encrypt', 'decrypt'
        ]
        
        for perm_name in permissions:
            existing_perm = Permission.query.filter_by(name=perm_name).first()
            if not existing_perm:
                new_perm = Permission(name=perm_name, description=f"Permission to {perm_name}")
                db.session.add(new_perm)
        
        db.session.commit()

@admin_bp.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin rights required.', 'danger')
        return redirect(url_for('admin_bp.manage_users'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_bp.manage_users'))

from flask import current_app
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Track if password was changed
        password_changed = False
        
        if username:
            current_user.username = username
        
        if email:
            current_user.email = email
        
        if password:
            # Check password complexity (optional)
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('profile'))
            
            current_user.password_hash = generate_password_hash(password)
            password_changed = True
        
        # Save changes to the database
        try:
            db.session.commit()
            
            # Send email notification if password was changed
            if password_changed:
                mail = Mail(current_app)
                msg = Message('Password Changed', 
                              sender=current_app.config['MAIL_DEFAULT_SENDER'],
                              recipients=[current_user.email])
                msg.body = f"""
                Hello {current_user.username},

                Your account password has been changed. 
                If you did not make this change, please contact support immediately.

                Best regards,
                Your Application Team
                """
                mail.send(msg)
            
            flash('Profile updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating your profile', 'danger')
        
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=current_user)

def assign_all_permissions_to_admin():
    with app.app_context():
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='Administrator role with full permissions')
            db.session.add(admin_role)
            db.session.commit()
        
        all_permissions = Permission.query.all()
        for perm in all_permissions:
            if not RolePermission.query.filter_by(role_id=admin_role.id, permission_id=perm.id).first():
                role_permission = RolePermission(role_id=admin_role.id, permission_id=perm.id)
                db.session.add(role_permission)
        
        db.session.commit()
        print("All permissions assigned to admin.")

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_bp.admin_dashboard')) 
        else:
            return redirect(url_for('index')) 

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        token = request.form.get('token')

        if not username or not password:
            app.logger.warning("Login attempt with missing credentials")
            return jsonify({'error': 'Username and password are required'}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            app.logger.warning(f"Login attempt for non-existent user: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401

        if not check_password_hash(user.password_hash, password):
            app.logger.warning(f"Failed password attempt for user: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401

        if user.totp_secret:
            if not token:
                app.logger.warning(f"MFA token missing for user: {username}")
                return jsonify({'error': 'MFA token required'}), 400
            if not verify_totp_token(user.totp_secret, token):
                app.logger.warning(f"Invalid MFA token for user: {username}")
                return jsonify({'error': 'Invalid MFA token'}), 401
        
        # Log the user in
        login_user(user)

        # Send login notification email
        try:
            msg = Message(
                "Login Notification",
                sender="sirinefakhfakh03@example.com",
                recipients=[user.email]  # Assumes `user.email` stores the user's email address
            )
            msg.body = f"""
            Hello {user.username},

 We hope this message finds you well.

 We wanted to inform you that you have successfully logged into your account. We’re thrilled to have you back! If you need any assistance or have any questions, feel free to reach out to our support team at any time.

For your security, remember to keep your login details confidential and avoid sharing them with anyone. If you notice any suspicious activity on your account, please contact us immediately.

 Thank you for choosing our service. We appreciate your trust and look forward to serving you.

  Best regards,
Cyrine security App Team
                                        """

            mail.send(msg)
            app.logger.info(f"Login notification email sent to {user.email}")
        except Exception as e:
            app.logger.error(f"Failed to send login email to {user.email}: {e}")

        if user.role == 'admin':
            return jsonify({'redirect': url_for('admin_bp.admin_dashboard')})
        else:
            return jsonify({'redirect': url_for('index')})
    
    return render_template('login.html')

def verify_totp_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already exists', 'error')
            return redirect(url_for('register'))
        
        
        password_hash = generate_password_hash(password)
        
        # Create a new user
        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        
        try:
            # Generate TOTP secret
            totp_secret = pyotp.random_base32()
            new_user.totp_secret = totp_secret
            db.session.commit()
            
            # Generate QR code for MFA
            totp = pyotp.TOTP(totp_secret)
            qr_uri = totp.provisioning_uri(name=username, issuer_name="YourAppName")
            qr_image = qrcode.make(qr_uri)
            qr_buffer = io.BytesIO()
            qr_image.save(qr_buffer, format="PNG")
            qr_buffer.seek(0)
            
            # Send email with QR code as attachment
            app.logger.info("Attempting to send MFA setup email")
            msg = Message('Set up your MFA', sender='sirinefakhfakh03@gmail.com', recipients=[email])
            msg.body = f"""
            Dear {username},

            Welcome to YourAppName! To enhance your account security, please set up Multi-Factor Authentication (MFA).

            Please find attached the QR code you need to scan using your authenticator app.

            Alternatively, you can use this secret code: {totp_secret}

            Thank you for joining us!
            YourAppName Team
            """
            msg.html = f"""
            <html>
            <body>
                <p>Dear {username},</p>
                <p>Welcome to <strong>Azure security simulator</strong>! To enhance your account security, please set up Multi-Factor Authentication (MFA).</p>
                <p>Scan the QR code attached or use this secret code: <strong>{totp_secret}</strong></p>
                <p>If you're ready, click the button below to set up your MFA:</p>
                <p style="text-align:center;">
                    <a href="{qr_uri}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Set Up MFA</a>
                </p>
                <p>Thank you for joining us!<br>YourAppName Team</p>
            </body>
            </html>
            """
            msg.attach('mfa_qr_code.png', 'image/png', qr_buffer.read())
            mail.send(msg)
            
            flash('Account created successfully! Please check your email to set up MFA.', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            app.logger.error(f"Failed to send MFA setup email: {str(e)}")
            db.session.delete(new_user)
            db.session.commit()
            flash('Failed to send MFA setup email. Please try again.', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')



@app.route('/logout', methods=['POST'])
@login_required
def logout():
    username = current_user.username
    app.logger.info(f"Attempting to log out user: {username}")
    logout_user()
    app.logger.info(f"User {username} logged out successfully")
    return redirect(url_for('login'))



@app.route('/security-center')
@login_required
def security_center():
    # Pagination support
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Adjust as needed
    
    # Paginate security events
    events_query = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc())
    events_pagination = events_query.paginate(page=page, per_page=per_page)
    
    return render_template('security_center.html', 
                           events=events_pagination.items,
                           total_events=events_pagination.total,
                           current_page=page,
                           total_pages=events_pagination.pages)

@app.route('/sentinel')
@login_required
def sentinel():
    # Get all security events and analyze patterns
    events = SecurityEvent.query.all()
    analysis = analyze_security_events(events)
    return render_template('sentinel.html', analysis=analysis)

def analyze_security_events(events):
    # Simple security analysis logic
    analysis = {
        'total_events': len(events),
        'high_severity': len([e for e in events if e.severity == 'HIGH']),
        'medium_severity': len([e for e in events if e.severity == 'MEDIUM']),
        'low_severity': len([e for e in events if e.severity == 'LOW']),
        'recent_threats': []
    }
    
    # Identify potential threats
    for event in events[-10:]:  # Look at last 10 events
        if event.severity in ['HIGH', 'MEDIUM']:
            analysis['recent_threats'].append({
                'timestamp': event.timestamp,
                'description': event.description,
                'severity': event.severity
            })
    
    return analysis





class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=50, message="Username must be between 3 and 50 characters")
    ])
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(message="Invalid email address")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    role = SelectField('User Role', choices=[
        ('user', 'Regular User'), 
        ('admin', 'Administrator'), 
        ('manager', 'Manager')
    ], validators=[DataRequired()])
    submit = SubmitField('Create User')

    def validate_username(self, username):
        """Custom validator to check if username already exists"""
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('Username already exists. Please choose a different username.')

    def validate_email(self, email):
        """Custom validator to check if email already exists"""
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError('Email already registered. Please use a different email.')

def handle_database_error(e):
    db.session.rollback()
    app.logger.error(f'Database error: {str(e)}')
    flash('An error occurred. Please try again later.', 'error')



@admin_bp.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('Access denied. Admin rights required.', 'danger')
        return redirect(url_for('index'))

    form = CreateUserForm()
    
    if form.validate_on_submit():
        try:
            # Check if role exists before creating
            role = Role.query.filter_by(name=form.role.data).first()
            if not role:
                flash('Selected role does not exist.', 'danger')
                return render_template('admin/create_user.html', form=form)

            new_user = User(
                username=form.username.data,
                email=form.email.data,
                role=form.role.data,
                role_relation=role,  # Set the role relationship
                password_hash=generate_password_hash(form.password.data)
            )
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f'User {new_user.username} created by {current_user.username}')
            flash(f'User {new_user.username} created successfully!', 'success')
            return redirect(url_for('admin_bp.admin_dashboard'))
        
        except Exception as e:
            handle_database_error(e)
    
    return render_template('admin/create_user.html', form=form)





def generate_login_qr(user):
    # Générer un jeton JWT pour le login
    token = jwt.encode({
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    # Générer un QR code avec le lien contenant le token
    login_url = url_for('qr_login', token=token, _external=True)
    qr_image = qrcode.make(login_url)
    qr_buffer = io.BytesIO()
    qr_image.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    return qr_buffer
app.register_blueprint(admin_bp, url_prefix='/admin')





from werkzeug.utils import secure_filename
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
UPLOAD_FOLDER = './uploads'
ENCRYPTED_FOLDER = './encrypted'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER

def encrypt_file(file_data, key):
    """Encrypts the file using AES encryption"""
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(file_data) + encryptor.finalize()
    return encrypted_data

def decrypt_file(secret):
    """Decrypts the file using the stored encryption key"""
    # Decrypt the encryption key first
    encryption_key = cipher_suite.decrypt(secret.key)  # Decrypt the key using the same cipher_suite

    # Extract the IV (first 16 bytes)
    iv = secret.value[:16]  # The first 16 bytes are the IV
    encrypted_value = secret.value[16:]  # The rest is the encrypted file data

    # Decrypt the file content using the decryption key
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_value) + decryptor.finalize()

    return decrypted_data


def store_encrypted_file_and_key(filename, file_data, encryption_key):
    # Encrypt the file content
    encrypted_data, iv = encrypt_file(file_data, encryption_key)

    # Encrypt the encryption key itself (for storage)
    encrypted_key = cipher_suite.encrypt(encryption_key)  # Use a secure cipher_suite

    # Save encrypted file data (not just the path)
    encrypted_file_data = encrypted_data  # The encrypted content itself

    # Save the secret (file content and encryption key)
    secret = Secret(
        name=filename,
        value=encrypted_file_data,  # Store the encrypted file content here
        key=encrypted_key,  # Store the encrypted encryption key
        created_by=current_user.id
    )
    db.session.add(secret)
    db.session.commit()
    flash('File encrypted and key stored successfully', 'success')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file:
            # Secure the filename
            filename = secure_filename(file.filename)
            file_data = file.read()

            # Generate a random encryption key for this file
            encryption_key = os.urandom(32)  # AES 256-bit key

            # Encrypt the file data
            iv = os.urandom(16)  # Initialization vector
            cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = iv + encryptor.update(file_data) + encryptor.finalize()

            # Encrypt the key with a master key for secure storage
            encrypted_key = cipher_suite.encrypt(encryption_key)

            # Save the encrypted file
            encrypted_file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], f"encrypted_{filename}")
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)

            # Store metadata and key in the Secret database
            try:
                secret = Secret(
                    name=f"{filename}",
                    value=encrypted_file_path,
                    key=encrypted_key,  # Store the encrypted key
                    created_by=current_user.id
                )
                db.session.add(secret)
                db.session.commit()
                flash('File encrypted and key stored successfully', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Failed to store encrypted file and key: {str(e)}")
                flash('Failed to save encryption data', 'error')

            return redirect(url_for('key_vault'))

    return render_template('upload.html')

@app.route('/download/<filename>')
def download_file(filename):
    """Allows users to download encrypted files."""
    return send_from_directory(app.config['ENCRYPTED_FOLDER'], filename, as_attachment=True)



@app.route('/key-vault')
@login_required
def key_vault():
    # Retrieve secrets for the current user
    secrets = Secret.query.filter_by(created_by=current_user.id).all()

    # Prepare a list of secrets (without decryption)
    secret_data = []
    for secret in secrets:
        secret_data.append({
            'id': secret.id,
            'name': secret.name,
            'value': secret.value,  # Display encrypted value (file data or path)
            'key': secret.key,  # Display encrypted key
            'created_at': secret.created_at
        })

    return render_template('key_vault.html', secrets=secret_data)

@app.route('/key-vault/add', methods=['POST'])
@login_required
def add_secret():
    try:
        name = request.form['name']
        value = request.form['value']
        
        # Validate input
        if not name or not value:
            flash('Secret name and value cannot be empty', 'error')
            return redirect(url_for('key_vault'))
        
        # Generate a random encryption key for this secret
        encryption_key = os.urandom(32)  # 256-bit key
        
        # Encrypt the value
        cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(os.urandom(16)), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_value = encryptor.update(value.encode()) + encryptor.finalize()
        
        # Encrypt the encryption key with a master key (cipher_suite)
        encrypted_key = cipher_suite.encrypt(encryption_key)
        
        # Save to database
        secret = Secret(name=name, value=encrypted_value, key=encrypted_key, created_by=current_user.id)
        db.session.add(secret)
        db.session.commit()
        
        app.logger.info(f"New secret '{name}' added by {current_user.username}")
        flash('Secret added successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding secret: {str(e)}")
        flash('Failed to add secret', 'error')
    
    return redirect(url_for('key_vault'))


def initialize_default_permissions():
    """
    Create default system permissions if they don't exist.
    This ensures critical permissions are always available.
    """
    default_permissions = [
        {'name': 'create_role', 'description': 'Create new user roles'},
        {'name': 'edit_role', 'description': 'Modify existing user roles'},
        {'name': 'delete_role', 'description': 'Remove user roles'},
        {'name': 'view_roles', 'description': 'View role details'},
        {'name': 'encrypt', 'description': 'Use encryption functionality'},
        {'name': 'decrypt', 'description': 'Use decryption functionality'},
        {'name': 'manage_users', 'description': 'Manage user accounts'},
        {'name': 'view_security_logs', 'description': 'Access security event logs'}
    ]

    with app.app_context():
        for perm_data in default_permissions:
            existing_permission = Permission.query.filter_by(name=perm_data['name']).first()
            if not existing_permission:
                new_permission = Permission(
                    name=perm_data['name'], 
                    description=perm_data['description']
                )
                db.session.add(new_permission)
        
        # Commit the new permissions
        db.session.commit()



if __name__ == '__main__':
    with app.app_context():
        init_db()
        init_permissions()
        initialize_default_permissions()
        assign_all_permissions_to_admin()
        check_user_permissions('firas')
        
    app.run(debug=True,port=5001)