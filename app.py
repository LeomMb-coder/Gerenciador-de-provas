from flask import flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask import abort
import os

app = Flask(__name__)
app.secret_key = 'Leo12345'  # Needed for session security

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Set up database path
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the Test model
class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))  # New field for image links
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Test {self.subject}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tests = db.relationship('Test', backref='author', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
#with app.app_context():
    #db.drop_all()
    #db.create_all()

#with app.app_context():
    #if not os.path.exists(os.path.join(basedir, 'tests.db')):
        #db.create_all()

@app.route('/create_db')
def create_db():
    db.create_all()
    return 'Database tables created!'

@app.route('/')
@login_required
def index():
    tests = Test.query.order_by(Test.date).all()
    return render_template('index.html', tests=tests)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    test = Test.query.get_or_404(id)

    # Only allow the test's author to edit
    if test.user_id != current_user.id:
        abort(403)  # Forbidden

    if request.method == 'POST':
        test.subject = request.form['subject']
        test.date = request.form['date']
        test.description = request.form['description']
        test.image_url = request.form['image_url']

        db.session.commit()
        return redirect(url_for('index'))

    return render_template('edit_test.html', test=test)

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        subject = request.form['subject']
        date = request.form['date']
        description = request.form['description']
        image_url = request.form['image_url']

        new_test = Test(
            subject=subject,
            date=date,
            description=description,
            image_url=image_url,
            user_id=current_user.id
        )
        db.session.add(new_test)
        db.session.commit()
        flash('Test added successfully!', 'success')

        return redirect(url_for('index'))

    return render_template('add_test.html')

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    test_to_delete = Test.query.get_or_404(id)
    db.session.delete(test_to_delete)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')  # 'danger' is a Bootstrap alert class
            return redirect(url_for('signup'))

            # After successful signup
        flash('User created successfully. Please login.', 'success')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully. Please login.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)