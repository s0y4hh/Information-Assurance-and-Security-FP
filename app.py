import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from models import db, User
from forms import LoginForm, RegistrationForm, EditProfileForm, ChangePasswordForm, ResetPasswordRequestForm, ResetPasswordForm
from utils import admin_required
from itsdangerous import URLSafeTimedSerializer, SignatureExpired


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB limit
app.config['PASSWORD_RESET_TOKEN_EXPIRES'] = 3600 # 1 hour


db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
@login_required
@admin_required
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            email=form.email.data,
            password_hash=hashed_password,
            role=form.role.data,
            first_name=form.first_name.data,  
            last_name=form.last_name.data     
        )
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully.', 'success')
        return redirect(url_for('users'))
    return render_template('register.html', form=form)


@app.route('/users')
@login_required
@admin_required
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        
        if form.profile_picture.data:
            try:
                file = form.profile_picture.data
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                if current_user.profile_picture and current_user.profile_picture != 'Default.jpg':
                  old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_picture)
                  if os.path.exists(old_file_path):
                      os.remove(old_file_path)

                current_user.profile_picture = filename
            except Exception:
                flash(f'Error uploading file: {e}', 'danger')
                return redirect(url_for('edit_profile'))

        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    return render_template('edit_profile.html', form=form)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Incorrect current password.', 'danger')
    return render_template('change_password.html', form=form)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('users'))
    if user.profile_picture != "default.jpg":
      file_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture)
      try:
          os.remove(file_path)
          print(f"File deleted: {file_path}")
      except FileNotFoundError:
          print(f"File not found: {file_path}")
      except Exception as e:
          print(f"Error deleting file: {file_path}, Error: {e}")

    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", "success")
    return redirect(url_for('users'))

@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')

            url_for('reset_password', token=token, _external=True)

            flash(f'Password reset link sent to {user.email}. Link expires in 1 hour', 'info')
            
        else:
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=app.config['PASSWORD_RESET_TOKEN_EXPIRES'])
    except SignatureExpired:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        flash('Error occurred while resetting password.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('Invalid request.', 'danger')
        return redirect(url_for('login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, token=token)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(413)
def too_large(error):
    return 'File is too large', 413

@app.before_request
def before_request():
    if request.endpoint in ['index', 'profile', 'users'] and not current_user.is_authenticated:
        return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@example.com').first():
            admin_user = User(
                email='admin@example.com',
                password_hash=generate_password_hash('admin'),
                role='admin',
                first_name='Admin',  
                last_name='User'     
            )
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=5000)
