import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash as gen_pwd_hash
import datetime
from datetime import datetime, timedelta

import pdb

from support import apology, login_required

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

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///mental.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

@app.route("/", methods=["GET"])
@login_required
def index():
    """Show my collections"""

    userid = session["user_id"]

    return render_template("index.html")


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        name = request.form.get("name")

        username = request.form.get("username")

        password = request.form.get("password")

        confirmation = request.form.get("confirmation")

        # Ensure fields were properly submitted
        # Ensure username was submitted
        if username == "" or len(username) <= 1:
            return apology("Please provide username.", 400)

        # Ensure password and password confirmation were submitted
        elif password == "" or confirmation == "":
            return apology("Please provide password.", 400)

        # Ensure password and confirm password are the same
        elif password != confirmation:
            return apology("Password and confirm password mismatch. Please try again.", 400)

        # Read already available usernames
        rows = db.execute("SELECT EXISTS (SELECT * FROM users where users.username = ?)", username)

        for k, v in rows[0].items():
            user_exists = v

        # Ensure username exists and password is correct
        if user_exists >= 1:
            return apology("Invalid username and/or password.", 400)

        else:
            # Register new user and password to database
            hash = gen_pwd_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

            result = db.execute("INSERT INTO users (name, username, hash) VALUES (:name, :username, :hash)", name=name, username=request.form.get("username"), hash=hash)

            # Remember which user has logged in
            session["username"] = username
            session["user_id"] = result

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/login/reset_pwd", methods=["GET", "POST"])
def reset_pwd():

    # URL reached out by POST method:
    if request.method == "POST":
        username = request.form.get("username")

        password = request.form.get("new_password")

        confirmation = request.form.get("new_confirmation")

        # Ensure fields were properly submitted
        # Ensure username was submitted
        if username == "" or len(username) <= 1:
            return apology("Please provide username.", 400)

        # Ensure password and password confirmation were submitted
        elif password == "" or confirmation == "":
            return apology("Please provide password.", 400)

        # Ensure password and confirm password are the same
        elif password != confirmation:
            return apology("Password and confirm password mismatch. Please try again.", 400)

        # Read already available usernames
        rows = db.execute("SELECT EXISTS (SELECT * FROM users where users.username = ?)", username)

        for k, v in rows[0].items():
            user_exists = v

        # Ensure username exists and password is correct
        if user_exists > 1:
            return apology("Invalid username and/or password.", 400)

        else:
            # Register new user and password to database
            new_hash = gen_pwd_hash(request.form.get("new_password"), method='pbkdf2:sha256', salt_length=8)

            pwd_update = db.execute('UPDATE users SET hash = ? WHERE username = ?', new_hash, username)

            # Remember which user has logged in
            session["username"] = username
            session["user_id"] = db.execute("SELECT id FROM users WHERE username = ?", username)[0].values

            # Redirect user to home page
            return redirect("/")

    # URL reached out by GET method:
    else:

        return render_template("reset_pwd.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/weekly_log", methods=["GET", "POST"])
@login_required
def weekly_log():

    cur_date = datetime.today()

    cur_dates_interval = db.execute("SELECT Week_of_Year, First_Date_of_Week, Last_Date_of_Week FROM calendar WHERE Calendar_Date == ?", str(cur_date.strftime("%d") + '/' + cur_date.strftime("%m") + '/' + cur_date.strftime("%Y")))[0]

    cur_week = cur_dates_interval['Week_of_Year']

    cur_start_week = cur_dates_interval['First_Date_of_Week']

    cur_last_week = cur_dates_interval['Last_Date_of_Week']

    calendar_entries = db.execute("SELECT * FROM calendar WHERE Week_of_Year == ?", cur_week)

    week_entries = []

    for item in calendar_entries:

        week_log = {}

        for key, value in item.items():

            if key == 'Calendar_Month' or key == 'Calendar_Day' or key == 'Calendar_Year' or key == 'Calendar_Quarter' or key == 'Day_of_Week' or key == 'Week_of_Year' or key == 'First_Date_of_Week' or key == 'Last_Date_of_Week':

                continue

            else:

                week_log[key] = value

                if key == 'Calendar_Date':
                    new_cur_date = datetime.strptime(value, '%d/%m/%Y')
                    cur_date_day = str(new_cur_date.day)

                    week_log['journal'] = db.execute("SELECT journal FROM journal WHERE user_id == ? AND week_no = ? AND date LIKE ?", session["user_id"], cur_week, '%' + cur_date_day)

                    i = 0
                    for i in range(len(week_log['journal'])):

                        if week_log['journal'] == [] or type(week_log['journal'][i]['journal']) == 'NoneType':

                            week_log['journal'] = '-'

                        else:

                            week_log['journal'][i] = week_log['journal'][i]['journal']

                    week_entries.append(week_log)

    if request.method == "POST":
        user_id = session["user_id"]

        new_entry_date = datetime.strptime(request.form.get("new_entry_date"), "%Y-%m-%d")
        week_no = new_entry_date.isocalendar()[1] + 1

        result = db.execute("INSERT INTO journal (user_id, journal, date, classifier, week_no, other2) VALUES (:user_id, :journal, :date, :classifier, :week_no, :other2)", user_id=user_id, journal=request.form.get("new_entry_task"), date=request.form.get("new_entry_date"), classifier=request.form.get("classifier"), week_no=week_no, other2='1')
        history = db.execute("INSERT INTO history (user_id, section, entry, date, other1) VALUES (:user_id, :section, :entry, :date, :other1)", user_id=user_id, section='Week Log', entry=request.form.get("new_entry_task"), date=datetime.now(), other1=1)
        return redirect("/weekly_log")

    else:

        return render_template("weekly_log.html", calendar=week_entries)



@app.route("/monthly_log", methods=["GET", "POST"])
@login_required
def monthly_log():

    cur_date = datetime.today()

    cur_dates_interval = db.execute("SELECT Calendar_Month, Week_of_Year FROM calendar WHERE Calendar_Date == ?", str(cur_date.strftime("%d") + '/' + cur_date.strftime("%m") + '/' + cur_date.strftime("%Y")))[0]

    cur_month = cur_dates_interval['Calendar_Month']

    cur_month_weeks = cur_dates_interval['Week_of_Year']

    calendar_entries = db.execute("SELECT * FROM calendar WHERE Calendar_Month == ?", cur_month)

    month_entries = []

    for item in calendar_entries:

        month_log = {}

        for key, value in item.items():

            if key == 'Calendar_Month' or key == 'Calendar_Day' or key == 'Calendar_Year' or key == 'Calendar_Quarter' or key == 'Day_of_Week' or key == 'Week_of_Year' or key == 'First_Date_of_Week' or key == 'Last_Date_of_Week':

                continue

            else:

                month_log[key] = value

                if key == 'Calendar_Date':
                    new_cur_date = datetime.strptime(value, '%d/%m/%Y')

                    if new_cur_date.day < 10:
                        cur_date_day = '0' + str(new_cur_date.day)
                    else:
                        cur_date_day = str(new_cur_date.day)

                    if new_cur_date.month < 10:
                        cur_date_mon = '0' + str(new_cur_date.month)
                    else:
                        cur_date_mon = str(new_cur_date.month)

                    cur_date_yea = str(new_cur_date.year)

                    new_cur_month = datetime.strftime(new_cur_date, '%m')
                    new_cur_date = cur_date_yea + "-" + cur_date_mon + "-" + cur_date_day

                    month_log['journal'] = db.execute("SELECT journal FROM journal WHERE user_id == ? AND strftime('%m', date) == ? AND date == ?", session["user_id"], new_cur_month, new_cur_date)

                    i = 0
                    for i in range(len(month_log['journal'])):

                        if month_log['journal'] == [] or type(month_log['journal'][i]['journal']) == 'NoneType':

                            month_log['journal'] = '-'

                        else:

                            month_log['journal'][i] = month_log['journal'][i]['journal']

                    month_entries.append(month_log)

    if request.method == "POST":
        user_id = session["user_id"]

        new_entry_date = datetime.strptime(request.form.get("new_entry_date"), "%Y-%m-%d")
        week_no = new_entry_date.isocalendar()[1] + 1

        result = db.execute("INSERT INTO journal (user_id, journal, date, classifier, week_no, other2) VALUES (:user_id, :journal, :date, :classifier, :week_no, :other2)", user_id=user_id, journal=request.form.get("new_entry_task"), date=request.form.get("new_entry_date"), classifier=request.form.get("classifier"), week_no=week_no, other2='1')
        history = db.execute("INSERT INTO history (user_id, section, entry, date, other1) VALUES (:user_id, :section, :entry, :date, :other1)", user_id=user_id, section='Month Log', entry=request.form.get("new_entry_task"), date=datetime.now(), other1=1)
        return redirect("/monthly_log")

    # URL reached out by GET method:
    else:

        return render_template("monthly_log.html", calendar=month_entries)


@app.route("/history", methods=["GET"])
@login_required
def history():

    if request.method == "GET":

        history = db.execute("SELECT section, entry, date FROM history WHERE user_id == ?", session["user_id"])

        return render_template("history.html", history=history)

@app.route("/brain_dump", methods=["GET", "POST"])
@login_required
def brains():

    if request.method == "POST":

        brain = db.execute("INSERT INTO brain (user_id, record, date, other1, other2) VALUES (:user_id, :record, :date, :other1, :other2)", user_id=session["user_id"], record=request.form.get("brain_dump"), date=datetime.now(), other1=1, other2='1')
        history = db.execute("INSERT INTO history (user_id, section, entry, date, other1) VALUES (:user_id, :section, :entry, :date, :other1)", user_id=session["user_id"], section='Brain Dump', entry=request.form.get("brain_dump"), date=datetime.now(), other1=1)

        return redirect("/")

    else:

        return render_template("brains.html")