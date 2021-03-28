from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm


app = Flask(__name__)
ckeditor = CKEditor(app)

app.config['SECRET_KEY'] = 'unknown_huynya'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///list.db'

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = '/login'
login_manager.login_message = "Пожалуйста, войдите, чтобы открыть эту страницу."


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.String(2000), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    date_release = db.Column(db.String(50), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    access_level = db.Column(db.Integer, nullable=False)

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/')
def index():
    name = ''
    try:
        name = current_user.name
    except Exception as ex:
        pass
    return render_template('index.html', name=name)


@app.route('/list_post')
@login_required
def list_post():

    search = request.args.get('search')
    if search:
        posts = Post.query.filter(Post.title.contains(search) |
                                  Post.content.contains(search) |
                                  Post.author.contains(search) |
                                  Post.date_release.contains(search)
                                  ).all()
    else:
        posts = Post.query.order_by(-Post.id)

    return render_template('list_post.html', posts=posts, search=1)

@app.route('/add_post')
def add_post():
    access_level = 1
    if current_user == None:
        redirect('/login')
    elif current_user.access_level > access_level:
        return render_template('ooops.html')

    return render_template('add_post.html')

@app.route('/save_post', methods=['POST'])
def save_post():
    access_level = 1
    if current_user == None:
        redirect('/login')
    elif current_user.access_level > access_level:
        return render_template('ooops.html')
    title = request.form['title']
    content = request.form.get('ckeditor')
    author = request.form['author']
    date_release = request.form['date_release']

    new_post = Post(title=title, content=content, author=author, date_release=date_release)

    try:
        db.session.add(new_post)
        db.session.commit()
    except Exception as ex:
        return ex.with_traceback()

    return redirect('/list_post')

@app.route('/save_user', methods=['POST'])
def save_user():

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    access_level = request.form['access_level']

    new_user = User(name=name, email=email, password=generate_password_hash(password, method='sha256'), access_level=access_level)
    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as ex:
        return ex.with_traceback()

    return redirect('/list_user')


@app.route('/update_post', methods=['POST', 'GET'])
def update_post():
    access_level = 1
    if current_user == None:
        redirect('/login')
    elif current_user.access_level > access_level:
        return render_template('ooops.html')

    id = request.form['id']
    title = request.form['title']
    content = request.form.get('ckeditor')
    author = request.form['author']
    date_release = request.form['date_release']
    update_post = Post.query.get_or_404(id)
    print(type(content))
    print('--->')
    print(content)

    try:
        update_post.title = title
        update_post.content = content
        update_post.author = author
        update_post.date_release = date_release

        db.session.commit()

    except Exception as update_error:
        print(update_error.__traceback__)

    return redirect('/list_post')

@app.route('/update_user', methods=['POST', 'GET'])
def update_user():
    access_level = 1
    if current_user == None:
        redirect('/login')
    elif current_user.access_level > access_level:
        return render_template('ooops.html')

    id = request.form['id']
    name = request.form['name']
    email = request.form['email']
    access_level = request.form['access_level']
    update_user = User.query.get_or_404(id)

    try:
        update_user.name = name
        update_user.email = email
        update_user.access_level = access_level
        db.session.commit()

    except Exception as update_error:
        print(update_error.__traceback__)


    return redirect('/list_user')

@app.route('/delete_post/<int:id>', methods=['GET'])
def delete_post(id):
    access_level = 1
    if current_user == None:
        redirect('/login')
    elif current_user.access_level > access_level:
        return redirect('/list_user')

    delete_post = Post.query.get_or_404(id)
    db.session.delete(delete_post)
    db.session.commit()
    return redirect('/list_post')

@app.route('/delete_user/<int:id>', methods=['GET'])
def delete_user(id):
    access_level = 0
    if current_user == None:
        redirect('/login')
    elif current_user.access_level > access_level:
        return render_template('ooops.html')

    delete_user = User.query.get_or_404(id)
    db.session.delete(delete_user)
    db.session.commit()
    return redirect('/list_user')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup_post', methods=['POST'])
def signup_post():
    access_level = 2

    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        return redirect('/signup')

    new_user = User(name=name, email=email, access_level=access_level, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()

    return redirect('/login')

@app.route('/login_post', methods=['POST'])
def login_post():

    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        flash('Проверьте свои данные и повторите попытку входа.')
        return redirect('/login')

    login_user(user=user, remember=remember)
    return redirect('/')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')

@app.route('/list_user')
def list_user():
    access_level = 0

    if not hasattr(current_user, 'access_level'):
        return redirect('/login')
    elif current_user.access_level > access_level:
        return render_template('ooops.html')
    else:
        search = request.args.get('search')
        if search:
            users = User.query.filter(
                User.name.contains(search) | User.email.contains(search) | User.access_level.contains(search)).all()
        else:
            users = User.query.order_by(-User.id)

        return render_template('list_user.html', search=1, users=users)




if __name__ == ('__main__'):
    app.run(debug=True)