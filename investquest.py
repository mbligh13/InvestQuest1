from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import yfinance as yf
app = Flask(__name__)


def CORS(app):
    pass


CORS(app)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:Investquest1!@investquest.c3o4s6swwij8.us-east-2.rds.amazonaws.com:3306/user_management'
app.config['SECRET_KEY'] = 'f3fe6d8491d6d0747213334e3df343bb'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login_post():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = user.username
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('create_account.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Implement password reset logic here
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        flash('You are not logged in!')
        return redirect(url_for('login'))
    return render_template('home.html', username=session['username'])

@app.route('/search_stocks', methods=['POST'])
def search_stocks():
    symbol = request.form['symbol']
    stock = yf.Ticker(symbol)
    info = stock.info
    if not isinstance(info, dict) or 'regularMarketPrice' not in info:
        info = "No data found"
        flash("Stock information unavailable or symbol not found.")
    else:
        info = {'regularMarketPrice': info.get('regularMarketPrice', 'Unavailable')}

    return render_template('stock_info.html', info=info)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
