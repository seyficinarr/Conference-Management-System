from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt


# Kayıt Formu
class RegisterForm(Form):
    firstName = StringField("First Name", validators=[validators.Length(min=3, max=25)])
    lastName = StringField("Last Name", validators=[validators.Length(min=3, max=25)])
    phone = StringField("Phone Number", validators=[validators.Length(min=10, max=25)])
    email = StringField("Email", validators=[validators.Email(message="The email address is invalid.")])
    password = PasswordField("Password:", validators=[
        validators.DataRequired(message="Please indicate a password"),
        validators.EqualTo(fieldname="confirm", message="Password did not match.")
    ])
    confirm = PasswordField("Confirm Password", validators=[validators.DataRequired()])
    role = StringField("Role")


app = Flask(__name__)


app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "foseproject"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)

@app.route("/")
def index():
    return render_template("layout.html")


@app.route("/articles")
def articles():
    return render_template("articles.html")


@app.route("/main_page")
def main_page():
    return render_template("main_page.html")


# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    


    if request.method == "POST" and form.validate():
        
        firstName = form.firstName.data
        lastName = form.lastName.data
        role = form.role.data
        email = form.email.data
        phone = form.phone.data
        password = sha256_crypt.encrypt(form.password.data)

        cursor = mysql.connection.cursor()

        sorgu = "Insert into user(firstName,lastName,role,email,phone,password) VALUES(%s,%s,%s,%s,%s,%s,%s)"

        cursor.execute(sorgu,(firstName,lastName,role,email,phone,password))
        mysql.connection.commit()

        cursor.close()
        return render_template("main_page.html",form = form)
    else:
        return render_template("register.html",form = form)


if __name__ == "__main__":
    app.run(debug=True)
