from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Initialize the database
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')
conn.commit()
conn.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'register' in request.form:
            # Register new user
            new_username = request.form['new_username']
            new_password = request.form['new_password']

            conn = sqlite3.connect('users.db', check_same_thread=False)
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=?", (new_username,))
            existing_user = c.fetchone()

            if existing_user:
                conn.close()
                return render_template('index.html', error='Username already exists')

            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, hashed_password))
            conn.commit()
            conn.close()

            return render_template('index.html', success='Registration successful! You can now log in.')

        else:
            # Login existing user
            username = request.form['username']
            password = request.form['password']

            conn = sqlite3.connect('users.db', check_same_thread=False)
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=?", (username,))
            user = c.fetchone()
            conn.close()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
                session['username'] = username
                return redirect(url_for('blog'))
            else:
                return render_template('index.html', error='Invalid username or password')

    return render_template('index.html')

@app.route('/blog')
def blog():
    if 'username' in session:
        return render_template('blog.html', username=session['username'])
    else:
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)