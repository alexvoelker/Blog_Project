from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps
from sqlalchemy.orm import relationship
from flask_gravatar import Gravatar
import os
from dotenv import load_dotenv

load_dotenv(".env")
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("PRODUCTION_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)


# #CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(1000), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    user_comments = relationship("Comment", back_populates="commenter")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author = relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    comments_on_post = relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    post = relationship("BlogPost", back_populates="comments_on_post")
    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    commenter = relationship("User", back_populates="user_comments")


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return func(*args, **kwargs)

    return decorated_function


def is_admin():
    if current_user.is_authenticated:
        return current_user.id == 1
    else:
        return False


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated,
                           is_admin=is_admin())


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        pre_hash_password = form.password.data
        hash_password = generate_password_hash(
            password=pre_hash_password,
            method=os.getenv("HASH_METHOD"),
            salt_length=8)

        new_email = form.email.data
        user = db.session.query(User).filter_by(email=new_email).first()
        if user:
            flash("User Already Exists", 'error')
        else:
            new_user = User(
                email=new_email,
                password=hash_password,
                name=form.name.data)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            flash("User Successfully Created", 'info')
            flash("Logged in successfully.", 'info')

            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = db.session.query(User).filter_by(email=email).first()
        if user:
            if check_password_hash(pwhash=user.password, password=password):
                login_user(user)
                flash("Logged in successfully.", 'info')
                return redirect(url_for('get_all_posts'))
        flash("Invalid Credentials", 'error')
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", 'info')
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()

    if current_user.is_authenticated:
        if comment_form.validate_on_submit():
            # Add a new comment to the form with commenting user's data
            new_comment = Comment(
                body=comment_form.comment_body.data,
                date=date.today().strftime("%B %d, %Y"),
                post_id=post_id,
                commenter_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()

    return render_template("post.html", post=requested_post, comments=requested_post.comments_on_post,
                           comment_form=comment_form, logged_in=current_user.is_authenticated, is_admin=is_admin())


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
# @login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    # Note: In order to enable users to edit their posts, nest the next code in the following if-statement
    # if post.author == current_user.name:
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)
    # flash("You need to be the author of this post to edit it!", "error")
    # return redirect(url_for("get_all_posts"))


@app.route("/delete/<int:post_id>")
# @login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)

    # Note: In order to enable users to edit their posts, nest the next code in the following if-statement
    # if current_user.name == post_to_delete.author:
    post_comments = post_to_delete.comments_on_post
    for comment in post_comments:
        db.session.delete(comment)
    db.session.delete(post_to_delete)
    db.session.commit()
    # else:
    #     flash("You must be the author of the post to delete it!", "error")

    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
