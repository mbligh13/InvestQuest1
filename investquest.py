from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import yfinance as yf
import csv

app = Flask(__name__)


# Function to get real-time stock data
def get_stock_data(symbol):
    try:
        # Get stock data using yfinance
        stock = yf.Ticker(symbol)
        stock_data = stock.info
        return stock_data
    except Exception as e:
        return {"error": str(e)}


# Function to fetch data for common indexes
def get_index_data():
    indexes = {
        'S&P 500': '^GSPC',
        'Dow Jones Industrial Average': '^DJI',
        'Nasdaq Composite': '^IXIC'
    }
    index_data = {}
    for name, symbol in indexes.items():
        data = get_stock_data(symbol)
        if 'error' not in data:
            index_data[name] = data
            # index_data[name]['regularMarketPrice'] = (data['ask'] + data['bid']) * 0.5
    index_data['S&P 500']['regularMarketPrice'] = (index_data['S&P 500']['ask'] + index_data['S&P 500']['bid'])*0.5

    index_data['Dow Jones Industrial Average']['regularMarketPrice'] = \
        (index_data['Dow Jones Industrial Average']['ask'] + index_data['Dow Jones Industrial Average']['bid']) * 0.5

    index_data['Nasdaq Composite']['regularMarketPrice'] = \
        index_data['Nasdaq Composite']['regularMarketOpen']

    index_data['S&P 500']['change'] = (index_data['S&P 500']['regularMarketPrice'] -
                                       index_data['S&P 500']['previousClose']) * 100 / index_data['S&P 500']['regularMarketPrice']

    index_data['Dow Jones Industrial Average']['change'] = \
        (index_data['Dow Jones Industrial Average']['regularMarketPrice'] -
         index_data['Dow Jones Industrial Average']['previousClose']) * 100 / index_data['Dow Jones Industrial Average']['regularMarketPrice']

    index_data['Nasdaq Composite']['change'] = \
        (index_data['Nasdaq Composite']['regularMarketPrice']-index_data['Nasdaq Composite']['previousClose'])*100 / index_data['Nasdaq Composite']['regularMarketPrice']

    return index_data


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
    role = db.Column(db.String(50), nullable=False)


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
            session['role'] = user.role  # Store the user's role in the session
            # Redirect based on user role
            if user.role == 'Admin':
                return redirect(url_for('user_management'))
            elif user.role == 'Customer Service':
                return redirect(url_for('user_management'))
            elif user.role == 'User':
                return redirect(url_for('home_portfolio'))
            else:

                flash('Your account does not have access to the system.')
                return redirect(url_for('login'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')


@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, role='User')

        db.session.add(new_user)
        try:
            db.session.commit()
            session['username'] = username
            session['role'] = 'User'
            flash('Account created successfully! Welcome, {}!'.format(username))
            return redirect(url_for('home_portfolio'))
        except:
            db.session.rollback()
            flash('Error creating account. Please try again.')
            return render_template('create_account.html')

    return render_template('create_account.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        return redirect(url_for('login'))
    return render_template('reset_password.html')


@app.route('/search_users', methods=['GET', 'POST'])
def search_users():
    if 'username' not in session or session['role'] not in ['Admin', 'Customer Service']:
        flash('Unauthorized access.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        search_query = request.form['search']
        users = User.query.filter(User.username.like(f"%{search_query}%")).all()
        return render_template('user_management.html', users=users)
    return render_template('user_management.html', users=[])


@app.route('/user_management', methods=['GET', 'POST'])
def user_management():
    if 'username' not in session:
        flash('Please log in to access this page.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')

        if action == 'Create' and session['role'] == 'Admin':
            return create_user()
        elif action == 'Reset Password' and session['role'] in ['Admin', 'Customer Service']:
            return reset_user_password(user_id)
        elif action == 'Delete' and session['role'] == 'Admin':
            return delete_user(user_id)
        else:
            flash('Unauthorized action or role.')
            return redirect(url_for('user_management'))

    if session['role'] in ['Admin', 'Customer Service']:
        users = User.query.all()
    else:
        users = []
        flash('Unauthorized to view this page.')
    return render_template('user_management.html', users=users)


def create_user():
    if 'role' in session and session['role'] == 'Admin':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('New user created successfully!')
        except:
            db.session.rollback()
            flash('Failed to create a new user. Please try again.')
    else:
        flash('Unauthorized action.')
    return redirect(url_for('user_management'))


def reset_user_password(user_id):
    if 'role' in session and session['role'] in ['Admin', 'Customer Service']:
        user = User.query.get(user_id)
        if user:
            new_password = 'reset_new_password'  # This should be securely generated or input by user
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            flash(f"Password for {user.username} has been reset.")
        else:
            flash("User not found.")
    else:
        flash('Unauthorized action.')
    return redirect(url_for('user_management'))


def delete_user(user_id):
    if 'role' in session and session['role'] == 'Admin':
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            flash(f"User {user.username} deleted successfully.")
        else:
            flash("User not found.")
    else:
        flash('Unauthorized action.')
    return redirect(url_for('user_management'))


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
    index_data = get_index_data()
    insights_data = calculate_insights(portfolio_data)

    # Inside your process_portfolio_data route
    return render_template('portfolio_insights.html', total_investment=insights_data[ 'total_investment' ],
                           total_sold=insights_data[ 'total_sold' ], total_profit=insights_data[ 'total_profit' ],
                           percentage=insights_data[ 'profit_percentage' ], analysis=insights_data[ 'analysis' ],
                           portfolio_data=portfolio_data, index_data=index_data)


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
    for ticker, date_bought, price_bought, date_sold, price_sold in zip(tickers, dates_bought, prices_bought,
                                                                        dates_sold, prices_sold):
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
    total_investment = sum(float(entry['price_bought']) for entry in portfolio_data)
    total_sold = sum(float(entry['price_sold']) for entry in portfolio_data if entry['price_sold'])
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
