from flask import Flask, render_template, request
from Crypto.Cipher import AES
from hashlib import sha256
import base64
import json
import os

app = Flask(__name__)

DATABASE = "data.json"

if not os.path.exists(DATABASE):
    with open(DATABASE, "w") as f:
        json.dump([], f)


def encrypt_data(text, master_password):

    key = sha256(master_password.encode()).digest()

    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(
        text.encode()
    )

    return base64.b64encode(
        cipher.nonce + tag + ciphertext
    ).decode()


def decrypt_data(data, master_password):

    raw = base64.b64decode(data)

    nonce = raw[:16]

    tag = raw[16:32]

    ciphertext = raw[32:]

    key = sha256(master_password.encode()).digest()

    cipher = AES.new(
        key,
        AES.MODE_EAX,
        nonce=nonce
    )

    text = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return text.decode()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/simpan", methods=["POST"])
def simpan():

    game = request.form.get("game")
    username = request.form.get("username")
    password = request.form.get("password")
    master = request.form.get("master")

    data = f"{username}|{password}"

    encrypted = encrypt_data(
        data,
        master
    )

    with open(DATABASE, "r") as f:
        db = json.load(f)

    db.append({
        "game": game,
        "data": encrypted
    })

    with open(DATABASE, "w") as f:
        json.dump(db, f)

    return render_template(
        "login.html",
        sukses=True
    )


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    hasil = []

    if request.method == "POST":

        master = request.form.get("master")

        with open(DATABASE, "r") as f:
            db = json.load(f)

        for item in db:

            try:

                data = decrypt_data(
                    item["data"],
                    master
                )

                username, password = data.split("|")

                hasil.append({

                    "game": item["game"],

                    "username": username,

                    "password": password

                })

            except:
                pass

    return render_template(
        "dashboard.html",
        hasil=hasil
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
