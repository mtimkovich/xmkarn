import os
import re
import random
import urllib2
import json
import hashlib
import hmac
import logging
import time
from string import letters

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

secret = "supersecret"

def make_secure_val(val):
    return "{0}|{1}".format(val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            "{0}={1}; Path=/".format(name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie("user_id", str(user.key().id()))

    def logout(self):
        self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie("user_id")
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith(".json"):
            self.format = "json"
        else:
            self.format = "html"

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
        time_fmt = "%c"

        d = {"subject": self.subject,
             "content": self.content,
             "created": self.created.strftime(time_fmt),
             "last_modified": self.last_modified.strftime(time_fmt)}
        return d

query_time = None
def get_posts(update = False):
    global query_time

    key = "posts"

    posts = memcache.get(key)

    if posts is None or update:
        logging.info("DB QUERY")
        posts = Post.all().order("-created")

        query_time = time.time()

        # prevents the running of multiple queries
        posts = list(posts)
        memcache.set(key, posts)

    return posts

def get_time_since_query(last_query):
    if query_time:
        time_since_query = format(time.time() - query_time, ".0f")
    else:
        time_since_query = "?"

    return time_since_query

class BlogFront(BlogHandler):
    def get(self):
        global query_time

        posts = get_posts()

        time_since_query = get_time_since_query(query_time)

        if self.format == "html":
            self.render('front.html', posts = posts, time_since_query = time_since_query)
        elif self.format == "json":
            self.render_json([p.as_dict() for p in posts])

class PostPage(BlogHandler):
    def get(self, post_id):
#         key = db.Key.from_path('Post', int(post_id), parent=blog_key())
#         post = db.get(key)

        posts = get_posts()

        post = None
        for p in posts:
            if p.key().id() == int(post_id):
                post = p

        if not post:
            self.error(404)
            return

        time_since_query = get_time_since_query(query_time)

        if self.format == "html":
            self.render("permalink.html", post = post, time_since_query = time_since_query)
        elif self.format == "json":
            self.render_json(post.as_dict())

class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()

            # rerun the query and update the cache
            get_posts(True)

            self.redirect('/blog/{0}'.format(str(p.key().id())))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class FlushPage(BlogHandler):
    def get(self):
        memcache.flush_all()

        self.redirect("/blog")

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()

    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "{0},{1}".format(salt, h)

def valid_pw(name, password, h):
    salt = h.split(",")[0]
    return h == make_pw_hash(name, password, salt)

def users_key():
    return db.Key.from_path('users')

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)

        if u:
            msg = "That user already exists"
            self.render("signup-form.html", error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            
            self.login(u)
            self.redirect("/blog/welcome")

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render("welcome.html", username = self.user.name)
        else:
            self.redirect("/blog/signup")

class Login(BlogHandler):
    def get(self):
        self.render("login-form.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect("/blog/welcome")
        else:
            msg = "Invalid login"
            self.render("login-form.html", username = username, error = msg)

class Logout(BlogFront):
    def get(self):
        self.logout()
        self.redirect("/blog/signup")

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
    markers = "&".join("markers={0},{1}".format(p.lat, p.lon)
                       for p in points)
    return GMAPS_URL + markers

#IP_URL ="http://api.hostip.info/?ip="
IP_URL = "http://api.hostip.info/get_json.php?position=true&ip="
def get_coords(ip):
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url)
    except URLError:
        return

    if content:
        j = json.load(content)

        lat = j['lat']
        lon = j['lng']

        if lat and lon:
            return db.GeoPt(lat, lon)

#     if content:
#         d = minidom.parseString(content)
#         coords = d.getElementsByTagName("gml:coordinates")
#         c = coords[0].childNodes[0].nodeValue
#         if coords and c:
#             lon, lat = c.split(",")
#             if lon and lat:
#                 return db.GeoPt(lat, lon)

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()

# arts = Art.gql("ORDER BY created DESC LIMIT 10")
def top_arts(update = False):
    key = "top"

    arts = memcache.get(key)

    if arts is None or update:
        logging.info("DB QUERY")
        arts = Art.all().order("-created").fetch(10)

        # prevents the running of multiple queries
        arts = list(arts)
        memcache.set(key, arts)

    return arts

class ASCIIChan(BlogHandler):
    def render_front(self, error="", title="", art=""):
        arts = top_arts()

        # find which arts have coords
        points = filter(None, (a.coords for a in arts))

        # if we have art coords, make an image url
        img_url = None
        if points:
            img_url = gmaps_img(points)

        self.render("asciichan.html", title = title, art = art,
                    error = error, arts = arts, img_url = img_url)

    def get(self):
        return self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")

        if title and art:
            p = Art(title = title, art = art)

            coords = get_coords(self.request.remote_addr)

            if coords:
                p.coords = coords

            p.put()
            # rerun the query and update the cache
            top_arts(True)

            self.redirect("/asciichan")

        else:
            error = "we need both a title and some artwork"
            self.render_front(error = error, title = title, art = art)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/blog/signup', Register),
                               ('/blog/welcome', Welcome),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/?(?:\.json)?', BlogFront),
                               ('/blog/([0-9]+)(?:\.json)?', PostPage),
                               ('/blog/flush', FlushPage),
                               ('/blog/newpost', NewPost),
                               ('/asciichan', ASCIIChan),
                               ],
                              debug=True)
