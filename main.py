#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2, cgi, jinja2, os, re
from google.appengine.ext import db
from datetime import datetime
import hashutils

# set up jinja
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))

# list of pages that anyone is allowed to visit (all others require loggin in)
allowed_routes = [
    "/login",
    "/logout",
    "/register"
]

class User(db.Model):
    """ Represents a user on this website. """
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)

class Food(db.Model):
    """ Represents a restaurant that a user wants to visit or has visited. """
    name = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    visited = db.BooleanProperty(required = True, default = False)
    datetime_visited = db.DateTimeProperty()
    rating = db.StringProperty()
    owner = db.ReferenceProperty(User, required = True)

class Handler(webapp2.RequestHandler):
    """ The base RequestHandler class for this app. The other Handlers inherit
    from this one. """

    def renderError(self, error_code):
        """ Sends an HTTP error code and a generic message to the client. """
        self.error(error_code)
        self.response.write("Uh, oh! Something went wrong!")

    def login_user(self, user):
        """ Logs in a user using the User object. """
        user_id = user.key().id()
        self.set_secure_cookie('user_id', str(user_id))

    def logout_user(self):
        """ Logs out the current user """
        self.set_secure_cookie('user_id', '')

    def read_secure_cookie(self, name):
        """ Returns the value associated with a name in the user's cookie or
        returns None if no value was found (or not valid). """
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return hashutils.check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        """ Adds a secure name-value pair cookie to the response. """
        cookie_val = hashutils.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def set_header(self):
        """ Attempt at adding the correct heading to stop an error """
        self.response.headers.send_header("Access-Control-Allow-Origin", "*")

    def initialize(self, *a, **kw):
        """ Any subclass of webapp2.RequestHandler can implement this method to
        specify what should happen before handling a request.

        This time its used to make sure a user is logged in. If the user is not logged
        in then they are redirected to the /login page. """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))

        if not self.user and self.request.path not in allowed_routes:
            self.redirect('/login')
            return

    def get_user_by_name(self, username):
        """ Given a username, try to fetch the user from the database """
        user = db.GqlQuery("SELECT * from User WHERE username = '%s'" % username)
        if user:
            return user.get()

class Index(Handler):
    """ Handles the requests coming into '/'. """

    def get(self):
        """ Display the homepage (with the list of places the user wants to visit). """
        query = Food.all().filter("owner", self.user).filter("visited", False)
        unvisited_food = query.run()

        t = jinja_env.get_template("frontpage.html")
        content = t.render(
                        foods = unvisited_food,
                        error = self.request.get("error"))
        self.response.write(content)

class AddFood(Handler):
    """ Handles requests coming in to '/add'. """

    def post(self):
        """ User can add a new restaurant to their list. """
        new_food_name = self.request.get("new-food")

        # if the user types nothing, redirect and let them know they have to.
        if (not new_food_name) or (new_food_name.strip() == ""):
            error = "Please enter a restaurant you want to visit!"
            self.redirect("/?error=" + cgi.escape(error))
            return

        # 'escape' the user's input so that if they type in HTML, it doesn't screw stuff up
        new_food_name_escaped = cgi.escape(new_food_name, quote = True)

        # construct a food object for the new restaurant
        food = Food(name = new_food_name_escaped, owner = self.user)
        food.put()

        # render the confirmation message
        t = jinja_env.get_template("add-confirmation.html")
        content = t.render(food = food)
        self.response.write(content)

class VisitedFood(Handler):
    """ Handles requests coming into '/visited-it'. """

    def post(self):
        """ User has visited a restaurant. """
        visited_food_id = self.request.get("visited-food")
        visited_food = Food.get_by_id(int(visited_food_id))

        # if we can't find the restaurant, the reject it.
        if not visited_food:
            self.renderError(400)
            return

        # update the food object to say the user visited the restaurant at a certain date in time
        visited_food.visited = True
        visited_food.datetime_visited = datetime.now()
        visited_food.put()

        # render confirmation page
        t = jinja_env.get_template("visited-it-confirmation.html")
        content = t.render(food = visited_food)
        self.response.write(content)

class FoodRatings(Handler):
    """ Handles requests coming into '/ratings'. """

    def get(self):
        """ Show a list of the restaurants the user has already visited. """
        # query for restaurants that the user has already visited
        query = Food.all().filter("owner", self.user).filter("visited", True)
        visited_food = query.run()

        t = jinja_env.get_template("ratings.html")
        content = t.render(foods = visited_food)
        self.response.write(content)

    def post(self):
        """ User wants to rate a restaurant. """

        rating = self.request.get("rating")
        food_id = self.request.get("food")

        food = Food.get_by_id(int(food_id))

        if food and rating:
            # update the rating of the food object
            food.rating = rating
            food.put()

            # render confirmation
            t = jinja_env.get_template("rating-confirmation.html")
            content = t.render(food = food)
            self.response.write(content)
        else:
            self.renderError(400)

class RecentlyVisitedFood(Handler):
    """ Handles request coming into '/recently-visited'. """

    def get(self):
        """ Display a list of restaurants that have recently been highly rated (by any user). """

        # query for visited movies (by any user), sorted by how high the movie was rated and how
        # recently the restaurant was visited
        query = Food.all().filter("visited", True).order("-rating").order("-datetime_visited")
        # get the first 25 results
        recently_visited_food = query.fetch(limit = 25)



        t = jinja_env.get_template("recently-visited.html")
        content = t.render(recently_visited_foods = recently_visited_food)
        self.response.write(content)

class UserVisitedFood(Handler):
    """ Handles request coming into '/user-visited'. """

    def get(self):
        """ Display a list of restaurants that have recently been highly rated (by any user). """

        # query for visited movies (by any user), sorted by how high the movie was rated and how
        # recently the restaurant was visited
        query = Food.all().filter("owner", self.user).filter("visited", True).order("-rating").order("-datetime_visited")
        # get the first 25 results
        user_visited_food = query.fetch(limit = 25)

        t = jinja_env.get_template("user-page.html")
        content = t.render(user_visited_foods = user_visited_food)
        self.response.write(content)

class Login(Handler):
    def render_login_form(self, error=""):
        t = jinja_env.get_template("login.html")
        content = t.render(error = error)
        self.response.write(content)

    def get(self):
        """ Display the login page. """
        self.render_login_form()

    def post(self):
        """ User is trying to log in. """
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")

        user = self.get_user_by_name(submitted_username)
        if not user:
            self.render_login_form(error = "Invalid Username!")
        elif not hashutils.valid_pw(submitted_username, submitted_password, user.pw_hash):
            self.render_login_form(error = "Invalid Password!")
        else:
            self.login_user(user)
            self.redirect("/")

class Logout(Handler):

    def get(self):
        """ User is trying to log out. """
        self.logout_user()
        self.redirect("/login")

class Register(Handler):

    def validate_username(self, username):
        """ Returns the username string if it is valid, if not then returns an empty string. """
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{5,20}$")
        if USER_RE.match(username):
            return username
        else:
            return ""

    def validate_password(self, password):
        """ Display the registration page. """
        PWD_RE = re.compile(r"^.{5,20}$")
        if PWD_RE.match(password):
            return password
        else:
            return ""

    def validate_verify(self, password, verify):
        """ Returns the password verification string if matched, otherwise returns an empty string. """
        if password == verify:
            return verify

    def get(self):
        """ Display the registration page. """
        t = jinja_env.get_template("register.html")
        content = t.render(errors={})
        self.response.out.write(content)

    def post(self):
        """ User is trying to register. """
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")
        submitted_verify = self.request.get("verify")

        username = self.validate_username(submitted_username)
        password = self.validate_password(submitted_password)
        verify = self.validate_verify(submitted_password, submitted_verify)

        errors = {}
        existing_user = self.get_user_by_name(username)
        has_error = False

        if existing_user:
            errors['username_error'] = "That username already exists!"
            has_error = True
        elif (username and password and verify):
            # create new user object
            pw_hash = hashutils.make_pw_hash(username, password)
            user = User(username=username, pw_hash=pw_hash)
            user.put()

            self.login_user(user)
        else:
            has_error = True

            if not username:
                errors['username_error'] = "That's not a valid username!"

            if not password:
                errors['password_error'] = "That's not a valid password!"

            if not verify:
                errors['verify_error'] = "Your passwords don't match!"

        if has_error:
            t = jinja_env.get_template("register.html")
            content = t.render(username=username, errors=errors)
            self.response.out.write(content)
        else:
            self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', Index),
    ('/add', AddFood),
    ('/visited-it', VisitedFood),
    ('/ratings', FoodRatings),
    ('/recently-visited', RecentlyVisitedFood),
    ('/user-visited', UserVisitedFood),
    ('/login', Login),
    ('/logout', Logout),
    ('/register', Register)
], debug=True)
