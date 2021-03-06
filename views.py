from flask import render_template, redirect, url_for, request, flash, session, Flask
from flask_login import login_required, current_user
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from passlib.hash import bcrypt
from . import live_module as mod_live
from application import cache
from application import CONFIG, app

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

MONGOLAB_URL = "mongodb://" + CONFIG['DB_USERNAME'] + ":" + CONFIG['DB_PASSWORD'] + "@" + CONFIG['DB_HOST'] + ":" + str(CONFIG['DB_PORT']) + "/" + CONFIG['DB_NAME']
client = MongoClient(MONGOLAB_URL)

db = client.get_default_database()
user_entry = db.user_entry
staff = db.staff
schedule_db = db.schedule
announcements = db.live_announcements
paths_db = db.paths

#User Model
class Admin(object):
  def __init__(self, _id):
    self._id = _id
    admin = staff.find_one({'_id' : ObjectId(_id)})
    if admin is not None:
      self.username = admin['username']

  def is_active(self):
    return True

  def is_anonymous(self):
    return False

  def is_authenticated(self):
    return True

  def get_id(self):
    return str(self._id)

  def full_name(self):
    return self.username

@login_manager.user_loader
def load_user(_id):
  if id is None:
    redirect('/admin')
  admin = Admin(_id)
  if admin.is_active():
    return admin
  return None

#login page for admin panel to set paths and workshops and schedule
@mod_live.route('/admin', methods=['GET', 'POST'])
def admin_login():
  if current_user.is_authenticated and current_user.is_active:
    return redirect('/dashboard')

  if request.method == 'POST':
    username = request.form['username']
    password = request.form['password']
    admin = staff.find_one({'username': username})
    
    #If authentication is successful, redirect to dashboard page
    if userAuth(admin, username, password):
      login_user(Admin(str(admin['_id'])))
      return redirect('/dashboard')

    else:
      return render_template('live.admin_login.html', error="Incorrect username or password.")
  
  return render_template('live.admin_login.html')

# dashboard, here you can see ios, hardware, web dev, scheduling buttons
@mod_live.route('/dashboard', methods=['GET', 'POST'])
@login_required
def view_dashboard():
  if (not current_user.is_authenticated):
    return redirect('/admin')

  return render_template('live.dashboard.html')

#ios path
@mod_live.route('/ios', methods=['GET', 'POST'])
@login_required
def ios():
  if (not current_user.is_authenticated()):
    return redirect('/admin')

  if request.method == 'POST':
    #phonenums = request.form['phonenums'] # string containing CSV of phonenums

    names = []
    phone_nums = []

    for i in range(100):
      curr_name = 'name' + str(i + 1) # name1 -> name100 will be the names from request.form
      curr_phone_num = 'phone' + str(i + 1)

      name = request.form[curr_name]
      digits = '0123456789'
      phone_temp = request.form[curr_phone_num]
      phone = ""

      for char in phone_temp: # Only keep the digits, in case someone enters the phone number in the wrong format
      	if char in digits:
      	  phone += char

      names.append(name)
      phone_nums.append(phone)
    
    paths_db.update_one({          # UPDATE array of hackers in this path
        'name': 'iOS'
        }, {
        '$set': {'hackers': names, 'phone_nums': phone_nums}
      })

    return redirect('/ios')

  hacker_names = paths_db.find_one({'name': 'iOS'})['hackers']
  phone_nums = paths_db.find_one({'name': 'iOS'})['phone_nums']

  return render_template('live.ios.html', hacker_names=hacker_names, phone_nums=phone_nums)

#hardware path
@mod_live.route('/hardware', methods=['GET', 'POST'])
@login_required
def hardware():
  if (not current_user.is_authenticated()):
    return redirect('/admin')

  if request.method == 'POST':
    #phonenums = request.form['phonenums'] # string containing CSV of phonenums

    names = []
    phone_nums = []

    for i in range(100):
      curr_name = 'name' + str(i + 1) # name1 -> name100 will be the names from request.form
      curr_phone_num = 'phone' + str(i + 1)

      name = request.form[curr_name]
      digits = '0123456789'
      phone_temp = request.form[curr_phone_num]
      phone = ""

      for char in phone_temp: # Only keep the digits, in case someone enters the phone number in the wrong format
      	if char in digits:
      	  phone += char

      names.append(name)
      phone_nums.append(phone)
    
    paths_db.update_one({          # UPDATE array of hackers in this path
        'name': 'Hardware'
        }, {
        '$set': {'hackers': names, 'phone_nums': phone_nums}
      })

    return redirect('/hardware')

  hacker_names = paths_db.find_one({'name': 'Hardware'})['hackers']
  phone_nums = paths_db.find_one({'name': 'Hardware'})['phone_nums']

  return render_template('live.hardware.html', hacker_names=hacker_names, phone_nums=phone_nums)
  
#web dev path
@mod_live.route('/web_dev', methods=['GET', 'POST'])
@login_required
def web_dev():
  if (not current_user.is_authenticated()):
    return redirect('/admin')

  if request.method == 'POST':
    #phonenums = request.form['phonenums'] # string containing CSV of phonenums

    names = []
    phone_nums = []

    for i in range(100):
      curr_name = 'name' + str(i + 1) # name1 -> name100 will be the names from request.form
      curr_phone_num = 'phone' + str(i + 1)

      name = request.form[curr_name]
      digits = '0123456789'
      phone_temp = request.form[curr_phone_num]
      phone = ""

      for char in phone_temp: # Only keep the digits, in case someone enters the phone number in the wrong format
      	if char in digits:
      	  phone += char

      names.append(name)
      phone_nums.append(phone)
    
    paths_db.update_one({          # UPDATE array of hackers in this path
        'name': 'Web Development'
        }, {
        '$set': {'hackers': names, 'phone_nums': phone_nums}
      })

    return redirect('/web_dev')

  hacker_names = paths_db.find_one({'name': 'Web Development'})['hackers']
  phone_nums = paths_db.find_one({'name': 'Web Development'})['phone_nums']

  return render_template('live.web_dev.html', hacker_names=hacker_names, phone_nums=phone_nums)

@mod_live.route('/edit_schedule', methods=['GET', 'POST'])
@login_required
def schedule():
  if (not current_user.is_authenticated()):
    return redirect('/admin')

  if request.method == 'POST':
    titles = []
    days = []
    times = []

    events_unsorted = []

    for i in range(121):					# Up to 120 scheduled events!
      curr_title_name = 'title' + str(i + 1)
      curr_day_name = 'day' + str(i + 1)
      curr_time_name = 'time' + str(i + 1)
      
      title = request.form[curr_title_name]
      day = request.form[curr_day_name]
      time = request.form[curr_time_name]
      spot = i + 1

      events_unsorted.append([title, day, time, spot])

    #events = sort(events_unsorted)

    # SAVE THE EVENTS IN DB
    for e in events_unsorted:
      if 'sat' in e[1].lower():		# Reformat day
      	e[1] = 'Sat'

      elif 'sun' in e[1].lower():
      	e[1] = 'Sun'


      schedule_db.update_one({
        'spot': e[3]
        }, {
        '$set': {'title': e[0], 'day': e[1], 'time': e[2]}
      })

    return redirect('/edit_schedule')

  events_unsorted = list(schedule_db.find())
  events = sort(events_unsorted)			# Load up schedule, Sort based on 'spot' parameter to put into calendar order

  titles = []
  days = []
  times = []
  spots = []

  for e in events:
  	titles.append(e['title'])
  	days.append(e['day'])
  	times.append(e['time'])
  	spots.append(float(e['spot']))

  #print(titles)
  
  return render_template('live.schedule.html', titles=titles, days=days, times=times, spots=spots)

def userAuth(user, username, password):
    if (user == None):
        return False
    return bcrypt.verify(password, user['password'])

@mod_live.route('/logout', methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect("/admin")

@mod_live.route('/live', methods=["GET", "POST"])
def live():
  schedule = get_schedule()
  primary = []
  ann = []

  for a in announcements.find():
    if a['primary'] == True:		# Main announcement
      primary = a
    else:
      ann.append(a)

  return render_template('live.live.html', schedule=schedule, primary=primary, announcements=ann)

def get_schedule():
  events_unsorted = []
  for s in schedule_db.find():
    events_unsorted.append(s)

  temp_events = sort(events_unsorted)
  events = [[], []]
  for e in temp_events:
    if len(e['title'].strip()) > 0: # Don't display empty schedule events on live site!
      if e['day'] == 'Sat':
        events[0].append(e)			# Saturday schedule
      else:
        events[1].append(e)			# Sunday schedule

  return events

# Takes in schedule object and sorts into calendar order
def sort(events):
  for j in range(len(events) - 1, 0, -1):
    for i in range(j):
      if float(events[i]['spot']) > float(events[i + 1]['spot']):
        temp = events[i]
        events[i] = events[i + 1]
        events[i + 1] = temp
  
  return events