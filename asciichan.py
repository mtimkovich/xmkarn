import os
import urllib2
import json

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
    markers = "&".join("markers={0},{1}".format(p.lat, p.lon)
                       for p in points)
    return GMAPS_URL + markers

# IP_URL = "http://api.hostip.info/?ip="
IP_URL = "http://api.hostip.info/get_json.php?position=true&ip="
def get_coords(ip):
    ip = "12.215.42.19"
    ip = "8.8.8.8"
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

        return db.GeoPt(lat, lon)

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()

class ASCIIChan(BlogHandler):
    def render_front(self, error="", title="", art=""):
        arts = Art.all().order("-created")

        # prevents the running of multiple queries
        arts = list(arts)

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

            self.redirect("/asciichan")

        else:
            error = "we need both a title and some artwork"
            self.render_front(error = error, title = title, art = art)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/asciichan', ASCIIChan),
                               ],
                              debug=True)
