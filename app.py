from flask import Flask, render_template, request, redirect, url_for, session
from db import init_db, seed_db 

from auth import authenticate_login as read_authenticate_login

import admin 
import user

import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

app.register_blueprint(admin.admin)
app.register_blueprint(user.user)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        response = read_authenticate_login(email, password)

        if response["status"] == "200":
            if response["data"]["is_admin"]:
                return redirect(url_for('admin.choice'))
            else:
                return redirect(url_for('user.dashboard'))
        else:
            return render_template('login.html')
    session.clear()
    return render_template('login.html')

if __name__ == '__main__':
    init_db()
    seed_db()
    app.run(debug=True)

    