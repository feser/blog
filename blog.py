import os

import jinja2
import webapp2
import hashlib
import hmac
import re
import random
import string
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

# definition of regular expressions and validation.used at signup page
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    return USER_RE.match(username) is not None


def valid_password(username):
    return PASSWORD_RE.match(username) is not None


def valid_email(username):
    return EMAIL_RE.match(username) is not None

# hashing methods, used to store hashed password and user id
SECRET = "imsosecret"


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=""):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(",")[1]
    return h == make_pw_hash(name, pw, salt)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace("\n", "<br>")
        t = jinja_env.get_template("post.html")
        like_count = Like.get_count_by_post_id(self.key().id())
        return t.render(p=self, like_count=like_count)

    @classmethod
    def get_by_id(cls, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        return post


class User(db.Model):
    user_id = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def get_user(cls, username):
        return db.GqlQuery(
            "SELECT * FROM User where user_id=:1", username).get()


class Comment(db.Model):
    content = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace("\n", "<br>")
        t = jinja_env.get_template("comment.html")
        return t.render(c=self)

    @classmethod
    def get_by_post_id(cls, post_id):
        return db.GqlQuery("SELECT * FROM Comment where post_id=:1 ORDER BY created DESC",
                           int(post_id))

    @classmethod
    def get_by_id(cls, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        return comment


class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def get_count_by_post_id(cls, post_id):
        like_count = db.GqlQuery(
            "SELECT * FROM Like where post_id=:1",
            int(post_id)).count()
        return like_count

    @classmethod
    def get_count_by_user_id(cls, user_id):
        like_count = db.GqlQuery(
            "SELECT * FROM Like where user_id=:1",
            int(user_id)).count()
        return like_count

# Main page handler


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(**params)

    def render(self, template, **kw):
        user = None
        # set logged in user
        if self.get_user():
            user = User.get_user(self.get_user())
        self.write(self.render_str(template, user=user, **kw))

    # returns logged in user
    def get_user(self):
        user_id_cookie_val = self.request.cookies.get("user_id")
        if user_id_cookie_val:
            username = check_secure_val(user_id_cookie_val)
            if username:
                return username

# main page of the blog, path = '/''


class MainPage(Handler):

    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        self.render("mainpage.html", posts=posts)

# new post page , path = '/newpost'


class NewPost(Handler):

    def get(self):
        if not self.get_user():
            self.redirect("/login")
            return
        self.render("postentry.html", post_title="New Post")

    def post(self):
        if not self.get_user():
            self.redirect("/login")
            return
        user = User.get_user(self.get_user())
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            post = Post(
                parent=blog_key(),
                subject=subject,
                content=content,
                user_id=user.key().id())
            post.put()
            self.redirect("/post/" + str(post.key().id()))
        else:
            error = "subject and content please!"
            self.render(
                "postentry.html",
                post_title="New Post",
                subject=subject,
                content=content,
                error=error)

# edit post page, path = '/edit/(.*)'


class EditPost(Handler):

    def get(self, post_id):
        if not self.get_user() or not post_id or not post_id.isdigit():
            self.redirect("/login")
            return
        post = Post.get_by_id(post_id)
        self.render("postentry.html", post_title="Edit Post", post=post)

    def post(self, post_id):
        if not self.get_user():
            self.redirect("/")
            return
        user = User.get_user(self.get_user())
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            post = Post.get_by_id(post_id)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect("/post/" + str(post.key().id()))
        else:
            error = "subject and content please!"
            self.render("postentry.html", post_title="Edit Post", subject=subject,
                        content=content, error=error)

# delete post page, path = '/delete/(.*)'


class DeletePost(Handler):

    def get(self, post_id):
        if not self.get_user() or not post_id or not post_id.isdigit():
            self.redirect("/login")
            return
        post = Post.get_by_id(post_id)
        post.delete()
        self.redirect("/")

# like post event, path = '/like/(.*)'


class LikePost(Handler):

    def get(self, post_id):
        if not self.get_user():
            self.redirect("/login")
            return
        user = User.get_user(self.get_user())
        like_count = Like.get_count_by_user_id(user.key().id())
        # if the user liked the post, return
        if like_count > 0:
            self.redirect("/post/" + str(post_id))
            return
        post = Post.get_by_id(post_id)
        like = Like(user_id=user.key().id(), post_id=post.key().id())
        like.put()
        self.redirect("/post/" + str(post_id))

# new comment page, path = '/comment/add/(.*)'


class NewComment(Handler):

    def get(self, post_id):
        if not self.get_user():
            self.redirect("/login")
            return
        self.render(
            "commententry.html",
            post_id=post_id,
            comment_title="New Comment")

    def post(self, post_id):
        if not self.get_user():
            self.redirect("/login")
            return
        if not post_id or not post_id.isdigit():
            self.redirect("/")
            return
        content = self.request.get("content")
        if content:
            post = Post.get_by_id(post_id)
            user = User.get_user(self.get_user())
            comment = Comment(
                content=content,
                user_id=user.key().id(),
                post_id=post.key().id())
            comment.put()
            self.redirect("/post/" + str(post.key().id()))
        else:
            error = "content please!"
            self.render("commententry.html", comment_title="New Comment", content=content,
                        post_id=post_id, error=error)

# edit comment page, path = '/edit/(.*)'


class EditComment(Handler):

    def get(self, comment_id):
        if not self.get_user():
            self.redirect("/login")
            return
        comment = Comment.get_by_id(comment_id)
        self.render("commententry.html", comment_title="Edit Comment", content=comment.content,
                    post_id=comment.post_id)

    def post(self, comment_id):
        if not self.get_user():
            self.redirect("/login")
            return
        if not comment_id or not comment_id.isdigit():
            self.redirect("/")
            return
        comment = Comment.get_by_id(comment_id)
        if not comment:
            self.redirect("/")
            return
        content = self.request.get("content")
        if content:
            comment = Comment.get_by_id(comment_id)
            comment.content = content
            comment.put()
            self.redirect("/post/" + str(comment.post_id))
        else:
            error = "content please!"
            self.render("commententry.html", comment_title="Edit Comment", content=content,
                        post_id=comment.post_id, error=error)

# delete comment page, path = '/comment/delete/(.*)'


class DeleteComment(Handler):

    def get(self, comment_id):
        if not self.get_user():
            self.redirect("/login")
            return
        comment = Comment.get_by_id(comment_id)
        post_id = comment.post_id
        comment.delete()
        self.redirect("/post/" + str(post_id))

# shows post details, comments, edit/delete post, edit/delete comment
# path = '/post/(.*)'


class Permalink(Handler):

    def get(self, post_id):
        if not post_id or not post_id.isdigit():
            self.redirect("/")
            return
        post = Post.get_by_id(post_id)

        if not post:
            self.redirect("/")
            return
        comments = Comment.get_by_post_id(post_id)
        is_creator_of_post = False
        if self.get_user():
            is_creator_of_post = User.get_user(
                self.get_user()).key().id() == post.user_id

        self.render(
            "permalink.html",
            post=post,
            comments=comments,
            is_creator_of_post=is_creator_of_post)

# creates user account, path = '/signup'


class SignupHandler(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""
        if valid_username(username) is False:
            username_error = "That's not a valid username."
        if username:
            is_user_exists = db.GqlQuery(
                "SELECT * FROM User where user_id=:1", username)
            if is_user_exists.get() is not None:
                username_error = "That user already exists"

        if valid_password(password) is False:
            password_error = "That wasn't a valid password."
        elif password != verify:
            verify_error = "Your passwords didn't match."

        if email and valid_email(email) is False:
            email_error = "That's not a valid email."

        if username_error == "" and password_error == "" and verify_error == "" and email_error == "":
            hashed_password = make_pw_hash(username, password, make_salt())
            user = User(
                user_id=username,
                password=hashed_password,
                email=email)
            user.put()
            self.response.headers.add_header(
                'Set-Cookie',
                "user_id=%s; Path=/" %
                make_secure_val(
                    str(username)))
            self.redirect("/welcome")
        else:
            self.render("signup.html", username_error=username_error, password_error=password_error,
                        verify_error=verify_error, email_error=email_error, username=username, email=email)

# login page, path = '/login'


class LoginHandler(Handler):

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        login_error = "Invalid Login"
        if username and password:
            user = db.GqlQuery(
                "SELECT * FROM User where user_id=:1",
                username).get()
            if user is not None:
                if valid_pw(username, password, user.password):
                    login_error = ""
                    self.response.headers.add_header(
                        'Set-Cookie', "user_id=%s; Path=/" %
                        make_secure_val(
                            str(username)))
                    self.redirect("/welcome")
        if login_error:
            self.render("login.html", login_error=login_error)


# logout page, path = '/logout'
class LogoutHandler(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
        self.redirect("/")

# welcome page, opened after user login. path = '/welcome'


class WelcomeHandler(Handler):

    def get(self):
        user_id_cookie_val = self.request.cookies.get("user_id")
        if user_id_cookie_val:
            username = check_secure_val(user_id_cookie_val)
            if username:
                self.render("welcome.html", user_name=username)
        else:
            self.redirect("/signup")

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', NewPost),
                               ('/post/(.*)', Permalink),
                               ('/like/(.*)', LikePost),
                               ('/edit/(.*)', EditPost),
                               ('/delete/(.*)', DeletePost),
                               ('/comment/add/(.*)', NewComment),
                               ('/comment/edit/(.*)', EditComment),
                               ('/comment/delete/(.*)', DeleteComment),
                               ('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/welcome', WelcomeHandler)], debug=True)
