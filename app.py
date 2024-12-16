from flask import Flask, render_template, request, redirect, flash, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3


# COM O BANCO DE DADOS
SQL = "database.sql"
DATABASE = "database.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# USUÁRIO

class User(UserMixin):
    def __init__(self, nome, email, senha, tipo):
        self.nome = nome
        self.email = email
        self.senha = senha
        self.tipo = tipo
        self.id = None

    def save(self):
        conn = get_connection()
        conn.execute("INSERT INTO users(email, nome, senha, tipo) values(?,?,?,?)",
                     (self.email, self.nome, self.senha, self.tipo))
        conn.commit()
        conn.close()
        return True

    # buscar usuário
    @classmethod
    def find(cls, **kwargs):
        conn = get_connection()
        if 'email' in kwargs.keys():
            res = conn.execute(
                "SELECT * from users where email = ?", (kwargs['email'],))
        elif 'id' in kwargs.keys():
            res = conn.execute(
                "SELECT * from users where id = ?", (kwargs['id'],))
        else:
            raise AttributeError('A busca deve ser feita por email ou id.')
        data = res.fetchone()
        if data:
            user = User(nome=data['nome'], email=data['email'],
                        senha=data["senha"], tipo=data["tipo"])
            user.id = data['id']
            return user
        return None

    @classmethod
    def all(cls):
        conn = get_connection()
        users = conn.execute("SELECT * FROM users").fetchall()
        return users


app = Flask(__name__)
app.config["SECRET_KEY"] = "hide on bush"
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)


@login_manager.user_loader
def user_loader(user_id):
    return User.find(id=user_id)


@app.before_request
def criar_tabela():
    conn = get_connection()

    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT NOT NULL,
        senha TEXT NOT NULL,
        tipo TEXT)
""")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    conn = get_connection()
    usuarios = conn.execute("SELECT * FROM users")
    return render_template("index.html", usuarios=usuarios)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nome = request.form["nome"]
        tipo = request.form["tipo"]
        email = request.form["email"]
        senha = request.form["senha"]

        senha_hash = bcrypt.generate_password_hash(senha).decode("utf-8")

        user = User(nome=nome, email=email, senha=senha_hash, tipo=tipo)
        user.save()
        return redirect(url_for("index"))
    return render_template("register.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]

        user = User.find(email=email)

        if user:
            senha_hash = user.senha
            if bcrypt.check_password_hash(senha_hash, senha):
                login_user(user)
                return redirect(url_for("dashboard"))
            else:
                flash("Senha incorreta!", "error")
        else:
            flash("Usuário não encontrado", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    logout_user()
    return redirect(url_for("index"))