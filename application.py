from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash, abort
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Items, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import os
from flask.ext.httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog_app.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Verify user passord
@auth.verify_password
def verify_password(username, password):
    user = session.query(User).filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True


# Render the master page with catalogies and latest items
@app.route('/')
@app.route('/catalog')
def showMaster():
    # Check if user is logged in to send his state or not
    if 'username' in login_session:
        categories = session.query(Category)
        count = session.query(Items).count()
        latest = session.query(Items).offset(count-9)
        return render_template('catalog.html',
                               STATE=login_session['state'],
                               Categ=categories, Lat=latest)
    else:
        categories = session.query(Category)
        count = session.query(Items).count()
        latest = session.query(Items).offset(count-9)
        return render_template('catalog.html', Categ=categories, Lat=latest)


# Render this method to show one catalog items
@app.route('/catalog/<string:Categ>/items/')
def Catitems(Categ):
    # Check if this category exist showing it's items
    Cat = session.query(Category).filter_by(name=Categ).first()
    if Cat:
        all = session.query(Category)
        return render_template('cat-items.html', Allcat=all, Selcat=Cat)
    else:
        return redirect(url_for('showMaster'))


# Render this method to show one item description
@app.route('/catalog/<string:Categ>/<string:Sitem>/')
def Itemdesc(Categ, Sitem):
    Searched_Categ = session.query(Category).filter_by(name=Categ).first()
    # Check if requrided category exist
    if Searched_Categ:
        item_id = -1
        # Searching for our proposed item in category items
        for item in Searched_Categ.items:
            if item.name == Sitem:
                item_id = item.id

        if item_id == -1:
            flash('This catalog not contain specified item')
            return redirect(url_for('showMaster'))
        else:
            Searched_Item = session.query(Items).filter_by(id=item_id).first()
            return render_template('item-desc.html', Itemd=Searched_Item)
    else:
        flash('Requried catalog not exist')
        return redirect(url_for('showMaster'))


# Render this method to edit one item
@app.route('/catalog/<string:item>/<int:ID>/edit', methods=['GET', 'POST'])
def Edititem(item, ID):
    # Check if user logged in give him editing permission
    if 'username' in login_session:
        Edited = session.query(Items).filter_by(name=item,
                                                category_id=ID).first()
        # Render edit template with item want to be edited
        if request.method == 'GET':
            Cat = session.query(Category).all()
            if Edited:
                if Edited.user_id == login_session['user_id']:
                    return render_template('edit-item.html',
                                            EditedItem=Edited, CatAll=Cat)
                else:
                    flash('You are not authorized to edit this item')
                    return redirect(url_for('showMaster'))
            else:
                flash('Requested item not exist')
                return redirect(url_for('showMaster'))
        # Save the edited item
        else:
            if Edited.user_id == login_session['user_id']:
                Edited.name = request.form['name']
                Edited.description = request.form['des']
                Edited.category_id = request.form['Category']

                session.add(Edited)
                session.commit()
                flash('Item updated succesfully')
                return redirect(url_for('showMaster'))
    else:
        flash('Your aren\'t have permissions to this link')
        return redirect(url_for('showMaster'))


# Render this method to delete one item
@app.route('/catalog/<string:item>/<int:ID>/delete', methods=['GET', 'POST'])
def Deleteitem(item, ID):
    # Check if user logged in give him deleting permission
    if 'username' in login_session:
        Deleted = session.query(Items).filter_by(name=item,
                                                 category_id=ID).first()
        if request.method == 'GET':
            # Searching for required item to delete
            # and render conformation page
            if Deleted:
                if Deleted.user_id == login_session['user_id']:
                    return render_template('delete-item.html', DItem=Deleted)
                else:
                    flash('You are not authorized to delete this item')
                    return redirect(url_for('showMaster'))
            else:
                flash('Requested item not exist')
                return redirect(url_for('showMaster'))
        # Delete proposed item
        else:
            if Deleted.user_id == login_session['user_id']:
                session.delete(Deleted)
                session.commit()
                flash('Item deleted succesfully')
                return redirect(url_for('showMaster'))
    else:
        flash('Your aren''t have permissions to this link')
        return redirect(url_for('showMaster'))


# Render this method to be able to add new item
@app.route('/catalog/add', methods=['GET', 'POST'])
def Additem():
    # Check if user logged in give him adding permission
    if 'username' in login_session:
        Cat = session.query(Category).all()
        if request.method == 'GET':
            # Render template used to specify new item components
            return render_template('add-item.html', CatAll=Cat)
        # Add the new item with specified components
        else:
            Newitem = Items(name=request.form['name'],
                            description=request.form['des'],
                            category_id=request.form['Category'],
                            user_id=login_session['user_id'])
            session.add(Newitem)
            session.commit()
            flash('New item added succesfully')
            return redirect(url_for('showMaster'))

    else:
        flash('Your aren''t have permissions to this link')
        return redirect(url_for('showMaster'))


# Render this method to enable registeration with site
@app.route('/register', methods=['GET', 'POST'])
def Register():
    # Check if user already logged in,
    # don't give him permission to registeration template
    if 'username' in login_session:
        return redirect(url_for('showMaster'))
    # Render the registeration template
    if request.method == 'GET':
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        return render_template('register.html', STATE=state)
    # Create new user account
    else:
        # Check if this user already registered or not
        user_id = getUserID(request.form['email'])
        if user_id is None:
            user = User(provider='local',
                        username=request.form['UserName'],
                        email=request.form['email'])
            user.hash_password(request.form['Password'])
            session.add(user)
            session.commit()
            flash('Hello %s' % user.username)
            login_session['provider'] = user.provider
            login_session['username'] = user.username
            login_session['email'] = user.email
            login_session['user_id'] = user.id
            return redirect(url_for('showMaster'))
        else:
            flash('This email already registered')
            return render_template('register.html',
                                   STATE=login_session['state'],
                                   form=request.form)


# Render this method to able user from logging in
@app.route('/login', methods=['POST', 'GET'])
def Login():
    # Check if user already logged in,
    # don't give him permission to login template
    if 'username' in login_session:
        return redirect(url_for('showMaster'))
    # Render the login template
    if request.method == 'GET':
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        return render_template('login.html', STATE=state)
    else:
        if request.form['email'] and request.form['Password']:
            user_id = getUserID(request.form['email'])
            # Check if this user regiter with us or not
            if user_id is not None:
                user = getUserInfo(user_id)
                # Check if this user register with third party authoriztion
                # then local login in permission not allowed
                if user.provider == 'local':
                    # Check user password
                    if user.verify_password(request.form['Password']):
                        login_session['username'] = user.username
                        login_session['email'] = user.email
                        login_session['user_id'] = user.id
                        login_session['provider'] = 'local'
                        flash('Welcome %s' % user.username)
                        return redirect(url_for('showMaster'))
                    else:
                        flash('Incorrect Password')
                        state = ''.join(random.choice(string.ascii_uppercase +
                                                      string.digits)
                                        for x in xrange(32))
                        login_session['state'] = state
                        return render_template('login.html', STATE=state)
                else:
                    flash('Third party authorization requried')
                    state = ''.join(random.choice(string.ascii_uppercase +
                                                  string.digits)
                                    for x in xrange(32))
                    login_session['state'] = state
                    return render_template('login.html', STATE=state)
            else:
                flash('This Email not registered')
                state = ''.join(random.choice(string.ascii_uppercase +
                                              string.digits)
                                for x in xrange(32))
                login_session['state'] = state
                return render_template('login.html', STATE=state)


# Return our database catalogies in json format
@app.route('/catalog/json')
def catalogJSON():
    cat = session.query(Category).all()
    return jsonify(Categories=[r.serialize for r in cat])


# Return an item in json format
@app.route('/item/<int:itemid>/json')
def itemJSON(itemid):
    item = session.query(Items).filter_by(id=itemid).first()
    return jsonify(Item=item)

# Connect to our website through facebook authorization
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json',
                        'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?'\
          'grant_type=fb_exchange_token&client_id=%s&'\
          'client_secret=%s&fb_exchange_token=%s' % (app_id,
                                                     app_secret,
                                                     access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token
        exchange we have to split the token first on commas and select
        the first index which gives us the key : value for the server
        access token then we split it on colons to pull out the actual
        token value and replace the remaining quotes with nothing so that
        it can be used directly in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?'\
          'access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?'\
          'access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
  
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;'\
              'border-radius: 150px;-webkit-border-radius: 150px;'\
              '-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# Disconnect facebook authorization
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?'\
          'access_token=%s' % (facebook_id,
                               access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Connect to our website through google authorization
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already'
                                            'connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'\
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Disconnect google authorization
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not'
                                            'connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?'\
          'token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['state']
        del login_session['user_id']
        del login_session['provider']
        return redirect(url_for('showMaster'))
    else:
        response = make_response(json.dumps('Failed to revoke token for'
                                            'given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'username' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()

        elif login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['state']
            del login_session['provider']
            del login_session['username']
            del login_session['email']
            del login_session['facebook_id']
            del login_session['access_token']
            del login_session['picture']
            del login_session['user_id']
        else:
            del login_session['state']
            del login_session['username']
            del login_session['email']
            del login_session['user_id']
            del login_session['provider']

        flash("You have successfully been logged out.")
        return redirect(url_for('showMaster'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showMaster'))


# Implementing of csrf_token
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = login_session.pop('_csrf_token', None)
        if request.form:
            if not token or token != request.form.get('_csrf_token'):
                abort(403)


def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits)
                                               for _ in range(10))
    return login_session['_csrf_token']


# User Helper Functions
def createUser(login_session):
    newUser = User(provider=login_session['provider'],
                   username=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

if __name__ == '__main__':
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.secret_key = os.urandom(32)
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
