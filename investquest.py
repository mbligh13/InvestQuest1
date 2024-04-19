from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import yfinance as yf
import csv

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


app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)


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
            print("login successful")
            return redirect(url_for('home_portfolio'))
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
        try:
            db.session.commit()
            # Log the user in by setting the session variables
            session['username'] = username
            flash('Account created successfully! Welcome, {}!'.format(username))
            return redirect(url_for('home_portfolio'))
        except:
            db.session.rollback()
            flash('Error creating account. Please try again.')
            return redirect(url_for('create account'))
    return render_template('create_account.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Implement password reset logic here
        return redirect(url_for('login'))
    return render_template('reset_password.html')


@app.route('/home_portfolio')
def home_portfolio():
    if 'username' not in session:
        flash('Please log in to view this page.')
        return redirect(url_for('login'))
    username = session['username']
    return render_template('home_portfolio.html', username=username)


@app.route('/your-portfolio', methods=['POST'])
def process_portfolio_data():
    if 'file' in request.files:
        # CSV file upload case
        csv_file = request.files['file']
        portfolio_data = process_csv_file(csv_file)
    else:
        # Manual entry case
        tickers = request.form.getlist('stock[]')
        print(tickers)
        dates_bought = request.form.getlist('date_bought[]')
        prices_bought = request.form.getlist('price_bought[]')
        dates_sold = request.form.getlist('date_sold[]')
        prices_sold = request.form.getlist('price_sold[]')
        portfolio_data = process_manual_entry(tickers, dates_bought, prices_bought, dates_sold, prices_sold)
    insights_data = calculate_insights(portfolio_data)

    # Inside your process_portfolio_data route
    return render_template('portfolio_insights.html', total_investment=insights_data['total_investment'],
                           total_sold=insights_data['total_sold'], total_profit=insights_data['total_profit'],
                           analysis=insights_data['analysis'], portfolio_data=portfolio_data)


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


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


def process_csv_file(csv_file):
    portfolio_data = []
    # Process CSV file
    csv_reader = csv.reader(csv_file)
    # Check if there is at least one row of data in the CSV file
    try:
        header = next(csv_reader)
    except StopIteration:
        # No data found in the CSV file
        return portfolio_data

    # Process remaining rows
    for row in csv_reader:
        ticker, date_bought, price_bought, date_sold, price_sold = row
        entry = {
            'ticker': ticker,
            'date_bought': date_bought,
            'price_bought': price_bought,
            'date_sold': date_sold,
            'price_sold': price_sold
        }
        portfolio_data.append(entry)
    return portfolio_data


def process_manual_entry(tickers, dates_bought, prices_bought, dates_sold, prices_sold):
    portfolio_data = []
    for ticker, date_bought, price_bought, date_sold, price_sold in zip(tickers, dates_bought, prices_bought, dates_sold, prices_sold):
        entry = {
            'ticker': ticker,
            'date_bought': date_bought,
            'price_bought': price_bought,
            'date_sold': date_sold,
            'price_sold': price_sold
        }
        portfolio_data.append(entry)
    return portfolio_data


# Function to calculate personalized insights
def calculate_insights(portfolio_data):
    print(portfolio_data)
    total_investment = sum(float(entry[ 'price_bought' ]) for entry in portfolio_data)
    total_sold = sum(float(entry[ 'price_sold' ]) for entry in portfolio_data if entry[ 'price_sold' ])
    total_profit = total_sold - total_investment

    if total_investment > 0:
        profit_percentage = (total_profit / total_investment) * 100
    else:
        profit_percentage = 0

    if profit_percentage > 0:
        analysis = "Your portfolio is performing well!"
    else:
        analysis = "Your portfolio is not performing as expected. Consider reviewing your investments."

    return {
        'total_investment': total_investment,
        'total_sold': total_sold,
        'total_profit': total_profit,
        'profit_percentage': profit_percentage,
        'analysis': analysis
    }


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

