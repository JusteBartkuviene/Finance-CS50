import hashlib, binascii, os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    counter = 0
    rows = db.execute("SELECT * FROM current WHERE user_id = %s", session["user_id"])
    if len(rows) != 0:
        for row in rows:
            symbol = row["symbol"]
            dict = lookup(symbol)
            price = dict["price"]
            row.update({"price":price})

            shares = row["shares"]
            total_float = shares * price
            total = round(total_float, 2)
            row.update({"total":total})

            counter =  counter + total

            rows2 = db.execute("SELECT * FROM users WHERE id = %s", session["user_id"])
            cash = rows2[0]["cash"]
            cash = round(cash, 2)

        counter_all = counter + cash

        return render_template("index.html", rows=rows, cash=cash, counter_all=counter_all)
    else:
        rows2 = db.execute("SELECT * FROM users WHERE id = %s", session["user_id"])
        counter_all = 0
        cash_float = rows2[0]["cash"]
        cash = round(cash_float, 2)
        counter_all = counter_all + cash
        return render_template("index.html", cash=cash, counter_all=counter_all)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":

        symbol = request.form.get("symbol")
        if lookup(symbol) == None:
            return apology("no such symbol", 403)

        dict = lookup(symbol)
        price = dict["price"]
        name = dict["name"]

        shares = request.form.get("shares")

        total_amount = float(shares) * float(price)
        round_total = round(total_amount, 2)

        id = session["user_id"]
        rows = db.execute("SELECT cash FROM users WHERE id = %s", session["user_id"])
        cash_balance = rows[0]["cash"]

        if total_amount > cash_balance:
            return apology("not enough funds", 403)

        remaining_amount_float = cash_balance - total_amount
        remaining_amount = round(remaining_amount_float, 2)

        now = datetime.now()
        time = now.strftime("%Y/%m/%d %H:%M:%S")

        db.execute("INSERT INTO history (symbol, shares, price, time, user_id) VALUES (:symbol, :shares, :price, :time, :user_id)", symbol=symbol, shares=shares, price=price, time=time, user_id=id)
        db.execute("UPDATE users SET cash = %s WHERE id = %s", remaining_amount, id)

        rows = db.execute("SELECT * FROM current WHERE symbol = %s AND user_id = %s", symbol, session["user_id"])
        if len(rows) == 0:
            db.execute("INSERT INTO current (symbol, name, shares, user_id) VALUES (:symbol, :name, :shares, :user_id)", symbol=symbol, name=name, shares=shares, user_id=id)
        else:
            uptodate_shares = rows[0]["shares"]
            current_shares = uptodate_shares + int(shares)
            db.execute("UPDATE current SET shares = %s WHERE symbol = %s AND user_id = %s", current_shares, symbol, session["user_id"])

        flash("Bought!")
        return redirect("/")
        #return render_template("test.html", price=price, shares=shares, round_total=round_total, cash_balance=cash_balance, remaining_amount=remaining_amount, time=time, rows=rows)

@app.route("/history")
@login_required
def history():
    rows = db.execute("SELECT * FROM history WHERE user_id = %s ORDER BY time DESC", session["user_id"])
    if len(rows) != 0:
        for row in rows:
            symbol = row["symbol"]
            shares = row["shares"]
            price = row["price"]
            time = row["time"]

        return render_template("history.html", rows=rows)
    else:
        return render_template("history.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change users password"""
    if request.method=="GET":
        return render_template("change.html")

    if request.method=="POST":

        # Query database for password
        hash_db = db.execute("SELECT hash FROM users WHERE username = %s", session["user_id"])

        # Ensure username exists and password is correct
        if check_password_hash(hash_db, request.form.get("password")):
            return apology("invalid password", 403)

        password_new = request.form.get("password_new")
        if not request.form.get("password_new"):
            return apology("must provide new password", 403)

        password_new_again = request.form.get("password_new_again")
        if not request.form.get("password_new_again"):
            return apology("must provide new password twice", 403)

        if password_new != password_new_again:
            return apology("new passwords must match", 403)

        hash = generate_password_hash(password_new)

        db.execute("UPDATE users SET hash = %s WHERE id = %s", hash, session["user_id"])

        flash("Password changed!")
        # Redirect user to home page
        return redirect("/")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method=="GET":
        return render_template("quote.html")

    if request.method=="POST":
        symbol = request.form.get("symbol")
        if lookup(symbol) == None:
            return apology("no such symbol", 403)

        dict = lookup(symbol)
        name = dict["name"]
        price = dict["price"]
        symbol = dict["symbol"]

        return render_template("quote_results.html", name=name, symbol=symbol, price=price)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method=="GET":
        return render_template("register.html")

    else:
        username = request.form.get("username")
        if not request.form.get("username"):
            return apology("must provide name", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(rows) != 0:
            if rows[0]["username"] == username:
                return apology("name is already taken", 403)

        password = request.form.get("password")
        if not request.form.get("password"):
            return apology("must provide password", 403)

        password_again = request.form.get("password_again")
        if not request.form.get("password_again"):
            return apology("must provide password twice", 403)

        if request.form.get("password") != request.form.get("password_again"):
            return apology("passwords must match", 403)

        hash = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hash)

        rows = db.execute("SELECT id FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        flash("Registered!")
        # Redirect user to home page
        return redirect("/")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        return render_template("sell.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")
        if lookup(symbol) == None:
            return apology("no such symbol", 403)

        rows = db.execute("SELECT * FROM current WHERE symbol = %s AND user_id = %s", symbol, session["user_id"])

        if rows == 0:
            return apology("you have no such shares", 403)

        available_shares = rows[0]["shares"]
        shares_pos = int(request.form.get("shares"))
        if available_shares < shares_pos:
            return apology("you have less shares than are trying to sell", 403)

        shares = shares_pos * (-1)

        dict = lookup(symbol)
        price = dict["price"]
        name = dict["name"]

        total_amount = float(shares) * float(price)
        round_total = round(total_amount, 2)
       # round_total_neg = round_total * (-1)

        id = session["user_id"]
        rows = db.execute("SELECT cash FROM users WHERE id = %s", session["user_id"])
        cash_balance = rows[0]["cash"]

        remaining_amount_float = cash_balance - total_amount
        remaining_amount = round(remaining_amount_float, 2)

        now = datetime.now()
        time = now.strftime("%Y/%m/%d %H:%M:%S")

        db.execute("INSERT INTO history (symbol, shares, price, time, user_id) VALUES (:symbol, :shares, :price, :time, :user_id)", symbol=symbol, shares=shares, price=price, time=time, user_id=id)
        db.execute("UPDATE users SET cash = %s WHERE id = %s", remaining_amount, id)

        rows = db.execute("SELECT * FROM current WHERE symbol = %s AND user_id = %s", symbol, session["user_id"])

        uptodate_shares = rows[0]["shares"]
        current_shares = uptodate_shares + int(shares)
        db.execute("UPDATE current SET shares = %s WHERE symbol = %s AND user_id = %s", current_shares, symbol, session["user_id"])

        if current_shares == 0:
            db.execute("DELETE FROM current WHERE symbol = %s AND user_id = %s", symbol, session["user_id"])

        flash("Sold!")
        return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
