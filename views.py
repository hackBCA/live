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
@mod_live.route('/dashboard', methods=['GET'])
@login_required
def view_dashboard():
  if (not current_user.is_authenticated()):
    return redirect('/admin')

  return render_template('live.dashboard.html')

#ios path
@mod_live.route('/ios', methods=['GET', 'POST'])
@login_required
def ios():
  if (not current_user.is_authenticated()):
    return redirect('/admin')

  if request.method == 'POST':
    phonenums = request.form['phonenums']
    names = request.form['names']
    admin = staff.find_one({'username': username})

    for name in names:
      staff.update_one({          # UPDATE array of hackers in this path
        'name': 'iOS'
        }, {
        '$push': {'hackers': name}
      })

    else:
      return render_template('ios.html')
  
  return render_template('ios.html')

#ios path
@mod_live.route('/hardware', methods=['GET', 'POST'])
@login_required
def hardware():
  if (not current_user.is_authenticated()):
    return redirect('/admin')

  if request.method == 'POST':
    phonenums = request.form['phonenums']
    names = request.form['names']
    admin = staff.find_one({'username': username})

    for name in names:
      staff.update_one({          # UPDATE array of hackers in this path
        'name': 'Hardware'
        }, {
        '$push': {'hackers': name}
      })

    else:
      return render_template('hardware.html')
  
  return render_template('hardware.html')

#ios path
@mod_live.route('/web_dev', methods=['GET', 'POST'])
@login_required
def web_dev():
  if (not current_user.is_authenticated()):
    return redirect('/admin')

  if request.method == 'POST':
    phonenums = request.form['phonenums']
    names = request.form['names']
    admin = staff.find_one({'username': username})

    for name in names:
      staff.update_one({          # UPDATE array of hackers in this path
        'name': 'Web Development'
        }, {
        '$push': {'hackers': name}
      })

    else:
      return render_template('web_dev.html')
  
  return render_template('web_dev.html')

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

    for i in range(40):
      curr_title_name = 'title' + str(i)
      curr_day_name = 'days' + str(i)
      curr_time_name = 'times' + str(i)
      curr_spot = 'spot' + str(i)

      title = request.form[curr_title_name]
      day = request.form[curr_day_name]
      time = request.form[curr_time_name]
      spot = request.form[curr_spot]

      if len(str(title)) > 0:
        events_unsorted.append([title, day, time, spot])

    #DO STUFF HERE TO COLLECT EVERYTHING FROM SCHEDULE AND UPDATEEE
    events = sort(events_unsorted)

    # SAVE THE EVENTS IN SORTED ORDER
    for i in range(len(events)):
      schedule.update_one({
        'spot': (i + 1)
        }, {
        '$set': {'title': event[0], 'day': event[1], 'time': event[2]}
      })

    else:
      return render_template('update_schedule.html')
  
  return render_template('update_schedule.html')

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
    if a['primary'] == True:
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
    if e['day'] == 'Sat':
      events[0].append(e)
    else:
      events[1].append(e)

    print(events[1])

  return events

#takes in schedule object
def sort(events):
  for j in range(len(events) - 1, 0, -1):
    for i in range(j):
      if float(events[i]['spot']) > int(events[i + 1]['spot']):
        temp = events[i]
        events[i] = events[i + 1]
        events[i + 1] = temp
  
  return events