from datetime import datetime
from flask_wtf import FlaskForm
from arrow import now
from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import PrimaryKeyConstraint, and_
from wtforms import DateTimeField, DateTimeLocalField, Form, IntegerField, SelectField, StringField, PasswordField, TextAreaField, ValidationError, validators
from passlib.hash import sha256_crypt
from wtforms.validators import InputRequired
    

app = Flask(__name__)

# Set the secret key to some random bytes. Keep this really secret!
app.secret_key = 'your_secret_key'  # Replace 'your_secret_key' with a strong secret key

# Config MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Aseyfo58@localhost/foseproject'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Creating an instance of the SQLAlchemy class
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    userId = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(25), nullable=False)
    lastName = db.Column(db.String(25), nullable=False)
    phone = db.Column(db.String(25), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50))
    password = db.Column(db.String(255), nullable=False)  # Increased length for password field

# Registration Form
class RegisterForm(Form):
    firstName = StringField("First Name", validators=[validators.Length(min=3, max=25)])
    lastName = StringField("Last Name", validators=[validators.Length(min=3, max=25)])
    phone = StringField("Phone Number", validators=[validators.Length(min=11, max=21, message="Phone number must be between 11 characters long.")])
    email = StringField("Email", validators=[validators.Email(message="The email address is invalid.")])
    role = SelectField("Role", choices=[('User', 'User'), ('Author', 'Author'), 
                ('Reviewer', 'Reviewer'), ('Organizer', 'Organizer')])
    password = PasswordField("Password", validators=[
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

# Register route
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
  
    if request.method == "POST" and form.validate():
        firstName = form.firstName.data
        lastName = form.lastName.data
        role = form.role.data
        email = form.email.data
        phone = form.phone.data
        password = sha256_crypt.hash(form.password.data)  # Hash the password

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already registered', 'danger')
            return render_template("register.html", form=form)
        
        # Check if phone number already exists
        existing_user2 = User.query.filter_by(phone=phone).first()
        if existing_user2:
            flash('Phone number already registered', 'danger')
            return render_template("register.html", form=form)
        
        try:
            # Create new user instance with hashed password
            new_user = User(firstName=firstName, lastName=lastName, role=role, email=email, phone=phone, password=password)

            # Add user to session and commit to DB
            db.session.add(new_user)
            db.session.commit()

            flash('You are now registered and can log in', 'success')
            return redirect(url_for('main_page'))  # Redirect to 'main_page' endpoint
        except Exception as e:
            print(f"Error inserting data: {e}")
            flash('Error registering user', 'danger')
    
    return render_template("register.html", form=form)

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)

    if request.method == "POST" and form.validate():
        email = form.email.data
        password = form.password.data
        
        # Query the database for the user
        user = User.query.filter_by(email=email).first()

        if user and sha256_crypt.verify(password, user.password):
            flash('Login successful', 'success')
            session['logged_in'] = True
            session['user_id'] = user.userId
            session['user_role'] = user.role  # Store the user's role in the session
            return redirect(url_for('main_page'))  # Redirect to 'main_page' endpoint
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template("login.html", form=form)

# Login Form
class LoginForm(Form):
    email = StringField("Email", validators=[validators.Email(message="The email address is invalid.")])
    password = PasswordField("Password")

# Logout Route
@app.route("/logout")
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

# Index route
@app.route("/")
def index():
    return render_template("layout.html")

# Article model
class Article(db.Model):
    paperId = db.Column(db.Integer, primary_key=True)
    authorId = db.Column(db.Integer, nullable = False)
    content = db.Column(db.Text, nullable=False)
    title = db.Column(db.String(50), nullable=False)
    dateTime = db.Column(db.DateTime, default=datetime.utcnow)

# Route to display all articles
@app.route('/articles')
def display_articles():
    user_id = session['user_id']
    user = User.query.filter_by(userId = user_id).first()
    articles = Article.query.all()
    return render_template('articles.html', articles=articles, user=user)

@app.route("/main_page")
def main_page():
    if 'logged_in' not in session:
        flash('You need to be logged in to view this page', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = User.query.get_or_404(user_id)
    
    if user.role == 'User':
        registered_conferences_count = Participant.query.filter_by(userId=user_id).count()
    else:
        registered_conferences_count = 0

    if user.role == 'Author':
        published_articles_count = Article.query.filter_by(authorId=user_id).count()
    else:
        published_articles_count = 0

    if user.role == 'Organizer':
        created_conferences_count = Conference.query.filter_by(organizerId=user_id).count()
    else:
        created_conferences_count = 0
    
    return render_template(
        "main_page.html",
        user=user,
        registered_conferences_count=registered_conferences_count,
        published_articles_count=published_articles_count,
        created_conferences_count=created_conferences_count
    )

# Route to display full content of an article
@app.route('/article/<int:article_id>')
def article(article_id):
    article = Article.query.get_or_404(article_id)
    user = User.query.get_or_404(article.authorId)
    return render_template('article.html', article=article, user=user)
    
# Conference model
class Conference(db.Model):
    conferenceId = db.Column(db.Integer, primary_key=True)
    organizerId = db.Column(db.Integer, nullable = False)
    paperId = db.Column(db.Integer, nullable = False)
    title = db.Column(db.Text, nullable = False)
    startDateTime = db.Column(db.DateTime, default=datetime.utcnow)
    endDateTime = db.Column(db.DateTime, default=datetime.utcnow)
    place = db.Column(db.Text, nullable = False)
    capacity = db.Column(db.Integer, nullable = False)
    remainingCapacity = db.Column(db.Text, nullable=False)

# Route to display all conferences
@app.route('/conferences')
def display_conferences():
    user_id = session['user_id']
    user = User.query.filter_by(userId = user_id).first()
    conferences = Conference.query.all()
    articles = Article.query.all()
    return render_template('conferences.html', conferences=conferences, articles = articles, user=user)

# Route to the conference
@app.route('/conference/<int:conference_id>')
def conference(conference_id):
    conference = Conference.query.get_or_404(conference_id)
    paper = Article.query.get_or_404(conference.paperId)
    organizer = User.query.get_or_404(conference.organizerId)
    author = User.query.get_or_404(paper.authorId)
    return render_template('conference.html', conference=conference, paper=paper, organizer=organizer, author = author)

# participant model to track which users are attending which conferences

class Participant(db.Model):
    __tablename__ = 'participant'
    userId = db.Column(db.Integer, db.ForeignKey('user.userId'), nullable=False)
    conferenceId = db.Column(db.Integer, db.ForeignKey('conference.conferenceId'), nullable=False)
    __table_args__ = (
        PrimaryKeyConstraint('userId', 'conferenceId'),
    )


# Route to attend the conference
@app.route('/attend_conference/<int:conference_id>', methods=['POST'])
def attend_conference(conference_id):
    if 'logged_in' not in session:
        flash('You need to be logged in to attend a conference', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conference = Conference.query.get_or_404(conference_id)

    if conference.remainingCapacity <= 0:
        flash('This conference is full', 'danger')
        return redirect(url_for('display_conferences'))
    
    if Participant.query.get((user_id, conference_id)):
        flash('You are already registered to this conference.', 'danger')
        return redirect(url_for('display_conferences'))
    
    user_conference = Participant(userId=user_id, conferenceId=conference_id)
    db.session.add(user_conference)
    conference.remainingCapacity -= 1
    db.session.commit()
    
    flash('You have successfully registered for the conference', 'success')
    return redirect(url_for('registered_conferences'))



# Route to fetch conferences registered by the user
@app.route("/registered_conferences")
def registered_conferences():
    if 'logged_in' not in session:
        flash('You need to be logged in to view your registered conferences', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    # Query the Participant table to get conferences registered by the user
    user_conferences = Participant.query.filter_by(userId=user_id).all()
    user = User.query.filter_by(userId=user_id).first()

    # List to store fetched conferences
    conferences = []
    
    # Fetch each conference object using conferenceId from Participant table
    for participant in user_conferences:
        conference = Conference.query.get(participant.conferenceId)
        if conference:
            conferences.append(conference)
    
    now = datetime.now()
    return render_template("registered_conferences.html", conferences=conferences, now=now, user=user)

# Route to cancel registration for a conference
@app.route('/cancel_registration/<int:conference_id>', methods=['POST'])
def cancel_registration(conference_id):
    if 'logged_in' not in session:
        flash('You need to be logged in to cancel your registration', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Check if the user is registered for the conference
    participant = Participant.query.filter_by(userId=user_id, conferenceId=conference_id).first()
    if not participant:
        flash('You are not registered for this conference.', 'danger')
        return redirect(url_for('conference', conference_id=conference_id))
    
    # Remove the participant entry
    db.session.delete(participant)
    
    # Increment remaining capacity of the conference
    conference = Conference.query.get_or_404(conference_id)
    conference.remainingCapacity += 1
    
    db.session.commit()
    
    flash('Your registration has been cancelled successfully', 'success')
    return redirect(url_for('registered_conferences', conference_id=conference_id))

#Organizer

# Custom Validators
def validate_start_date(form, field):
    if field.data < datetime.utcnow():
        raise ValidationError("Start date must be after the current date and time.")

def validate_end_date(form, field):
    if field.data <= form.startDateTime.data:
        raise ValidationError("End date must be after the start date.")

class CreateConferenceForm(FlaskForm):
    title = StringField("Title", validators=[validators.Length(min=3, max=100)])
    startDateTime = DateTimeLocalField("Start Date and Time", format='%Y-%m-%dT%H:%M', validators=[validators.DataRequired(message="Start date is required"), validate_start_date])
    endDateTime = DateTimeLocalField("End Date and Time", format='%Y-%m-%dT%H:%M', validators=[validators.DataRequired(message="End date is required"), validate_end_date])
    place = StringField("Place", validators=[validators.Length(min=3, max=100)])
    capacity = IntegerField("Capacity", validators=[validators.NumberRange(min=1)])
    article_id = SelectField('Article', coerce=int, choices=[], validators=[InputRequired()])

@app.route('/create_conference', methods=['GET', 'POST'])
def create_conference():
    form = CreateConferenceForm(request.form)

    # Fetch articles and their authors for populating SelectField choices
    articles = db.session.query(Article, User).join(User, Article.authorId == User.userId).all()
    form.article_id.choices = [(article.paperId, f"{article.title} by {user.firstName} {user.lastName}") for article, user in articles]

    if request.method == 'POST' and form.validate():
        title = form.title.data
        startDateTime = form.startDateTime.data
        endDateTime = form.endDateTime.data
        place = form.place.data
        capacity = form.capacity.data
        article_id = form.article_id.data
        
        # Retrieve organizer ID from session or however you manage authentication
        organizer_id = session.get('user_id')
        
        # Check for date intersection at the same place
        conflicting_conferences = Conference.query.filter(
            and_(
                Conference.place == place,
                Conference.startDateTime < endDateTime,
                Conference.endDateTime > startDateTime
            )
        ).first()

        conflicting_titles = Conference.query.filter(Conference.title==title).first()

        if conflicting_titles:
            flash('The title of conference intersect with another conference.', 'danger')
            return render_template('create_conference.html', form=form)


        
        if conflicting_conferences:
            flash('The conference dates intersect with another conference at the same place.', 'danger')
            return render_template('create_conference.html', form=form)
        
        try:
            # Create new conference instance
            new_conference = Conference(
                organizerId=organizer_id,
                paperId=article_id,
                title=title,
                startDateTime=startDateTime,
                endDateTime=endDateTime,
                place=place,
                capacity=capacity,
                remainingCapacity=capacity  # Initially set remainingCapacity to full capacity
            )
            
            # Add conference to database
            db.session.add(new_conference)
            db.session.commit()
            
            flash('Conference created successfully', 'success')
            return redirect(url_for('created_conferences'))  # Redirect to conferences page
        except Exception as e:
            flash('Error creating conference', 'danger')
            print(f'Error: {str(e)}')
    
    return render_template('create_conference.html', form=form)

# Route to fetch conferences registered by the user
@app.route("/created_conferences")
def created_conferences():
    if 'logged_in' not in session:
        flash('You need to be logged in to view your created conferences', 'danger')
        return redirect(url_for('login'))

    organizer_id = session['user_id']
    
    # Query the Participant table to get conferences registered by the user
    organized_conferences = Conference.query.filter_by(organizerId=organizer_id).all()
    organizer = User.query.filter_by(userId=organizer_id).first()

    now = datetime.now()
    return render_template("created_conferences.html", now=now, organizer=organizer, conferences=organized_conferences)

# Route to cancel conference
@app.route('/cancel_conference/<int:conference_id>', methods=['POST'])
def cancel_conference(conference_id):
    if 'logged_in' not in session:
        flash('You need to be logged in to cancel your conference', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Check if the user is registered for the conference
    conference = Conference.query.filter_by(organizerId=user_id).first()
    if not conference:
        flash('You are not the organizer of the conference.', 'danger')
        return redirect(url_for('created_conferences', conference_id=conference_id))
    
    # Remove the participant entry
    db.session.delete(conference)
    
    db.session.commit()
    
    flash('Your conference has been cancelled successfully', 'success')
    return redirect(url_for('created_conferences', conference_id=conference_id))

#Author

class PublishArticleForm(FlaskForm):
    title = StringField("Title", validators=[validators.Length(min=3, max=100)])
    content = TextAreaField("Content", validators=[validators.DataRequired()])

@app.route("/publish_article", methods=['GET', 'POST'])
def publish_article():
    form = PublishArticleForm(request.form)
    author_id = session.get('user_id')

    if request.method == 'POST' and form.validate():
        title = form.title.data
        content = form.content.data

        try:
            # Create new article instance
            new_article = Article(
                authorId=author_id,
                title=title,
                content=content,
                dateTime=datetime.utcnow()
            )

            # Add article to database
            db.session.add(new_article)
            db.session.commit()

            flash('Article published successfully', 'success')
            return redirect(url_for('display_articles'))  # Redirect to articles page
        except Exception as e:
            flash('Error creating article', 'danger')
            print(f'Error: {str(e)}')

    return render_template('publish_article.html', form=form)

# Route to fetch articles published by the user
@app.route("/published_articles")
def published_articles():
    if 'logged_in' not in session:
        flash('You need to be logged in to view your published articles', 'danger')
        return redirect(url_for('login'))

    author_id = session['user_id']
    
    # Query the Participant table to get conferences registered by the user
    published_articles = Article.query.filter_by(authorId=author_id).all()
    author = User.query.filter_by(userId=author_id).first()

    return render_template("published_articles.html", author=author, articles=published_articles)

# Route to delete an article
@app.route('/delete_article/<int:article_id>', methods=['POST'])
def delete_article(article_id):
    if 'logged_in' not in session:
        flash('You need to be logged in to delete an article', 'danger')
        return redirect(url_for('login'))

    article = Article.query.get_or_404(article_id)

    # Check if the logged-in user is the author of the article
    if session['user_id'] != article.authorId:
        flash('You are not authorized to delete this article', 'danger')
        return redirect(url_for('display_articles'))

    try:
        db.session.delete(article)
        db.session.commit()
        flash('Article deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting article', 'danger')
        print(f'Error: {str(e)}')

    return redirect(url_for('display_articles'))






if __name__ == "__main__":
    app.run(debug=True)