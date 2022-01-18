from flask import Flask, request, jsonify,g,abort
import click
from flask.cli import with_appcontext
from functools import wraps
import json
from flask_security import Security, \
     SQLAlchemySessionUserDatastore
from db import db_session, init_db
from models import TokenBlackList, User, Role, Group, GroupsUsers, Messages, Likes
from flask_httpauth import HTTPBasicAuth
import os
auth = HTTPBasicAuth()

# Create app
def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'app.db'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    user_datastore = SQLAlchemySessionUserDatastore(db_session,
                                                User, Role)
    Security(app, user_datastore)
    return app, user_datastore

app, user_datastore = create_app()
app.config['DEBUG'] = True
# app.config['SECRET_KEY'] = 'super-secret'
# app.config['SECURITY_PASSWORD_SALT'] = 'super-salty'

# Setup Flask-Security


auth = HTTPBasicAuth()

# Create a user to test with
# Use this for the first time to create a admin password
# @app.before_first_request
# def create_user():
#     init_db()
#     user = user_datastore.create_user(email='abhinav@chat.net')
#     # user = User(email='abhinav@chat.net', password="adminpass")
#     user.hash_password(password='adminpass')
#     admin_role=user_datastore.create_role(name="admin", description="Creates and edits other users.")
#     normal_user_role=user_datastore.create_role(name="normal_user", description="Creates/edits groups, messages, members.")
#     # admin_role = Role(name="admin", description="Creates and edits other users.")
#     # normal_user_role = Role(name="normal_user", description="Creates/edits groups, messages, members.")
#     db_session.add(user)
#     db_session.add(admin_role)
#     db_session.add(normal_user_role)
#     user_datastore.add_role_to_user(user=user,role=admin_role)
#     db_session.commit()

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    user = user_datastore.create_user(email='abhinav@chat.net')
    user.hash_password(password='adminpass')
    normal_user = user_datastore.create_user(email='abhinav-normal@chat.net')
    normal_user.hash_password(password='normalpass')
    admin_role=user_datastore.create_role(name="admin", description="Creates and edits other users.")
    normal_user_role=user_datastore.create_role(name="normal_user", description="Creates/edits groups, messages, members.")
    db_session.add(user)
    db_session.add(normal_user)
    db_session.add(admin_role)
    db_session.add(normal_user_role)
    user_datastore.add_role_to_user(user=user,role=admin_role)
    user_datastore.add_role_to_user(user=user,role=normal_user_role)
    db_session.commit()
    click.echo('Initialized the database.')

def roles_accepted(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):  
            with app.app_context():
                user_roles = [role.name for role in request.user.roles]
                if len(set(user_roles).intersection(set(roles))) == 0:
                    return jsonify(msg="User is not authorized for the api."), 403

            return fn(*args, **kwargs)
        return decorated_view    
    return wrapper 



@auth.verify_password
def verify_password(username_or_token, password):
    if TokenBlackList.query.filter_by(blacklisted_token=username_or_token).first():
        return False
    user = User.verify_auth_token(username_or_token)

    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(email = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    else:
        g.token = username_or_token
    g.user = user
    request.user = user
    
    return True

# Views
@app.route('/api/login', methods = ['POST'])
@auth.login_required()
@roles_accepted('admin','normal_user')
def login():
    
    token = g.user.generate_auth_token()
    return jsonify({ 'token': token.decode('ascii') })

@app.route('/api/logout')
@auth.login_required
def logout():
    if g.token:
        token = TokenBlackList(user_id=g.user.id, blacklisted_token=g.token)
        db_session.add(token)
        db_session.commit()
    return jsonify(msg="Logged out succesfully")

# Admin apis create and edit user
@app.route('/api/user', methods=['POST', 'PUT'])
@auth.login_required
@roles_accepted('admin')
def users():
    if request.method == 'POST':
        try:
            data = request.json
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            
            if name and email and password:
                user = User(username=name, email=email)
                user.hash_password(password)
                user_datastore.add_role_to_user(user=user,role=user_datastore.find_role('normal_user'))
                db_session.commit()
                return {'msg':'User created successfully','user_id':user.id}
            else:
                return {'msg':'Please send all the parameters'}
        except:
            return jsonify(msg='Please send data in json')
    elif request.method == 'PUT':
        try:
            data = request.json
            user_id = data.get('user_id')
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            user = User.query.get(int(user_id))
            if user:
                if name:
                    user.username = name
                if email:
                    user.email = email
                if password:            
                    user.hash_password(password)
            else:
                return json.dumps({'msg':'Please send a user id'})
            if name or email or password:
                db_session.add(user)
                db_session.commit()
            return {'msg':'User edited successfully'}
        except:
            return jsonify(msg='Please send data in json')
        


@app.route('/api/list_users', methods=['GET'])
@auth.login_required
@roles_accepted('admin', 'normal_user')
def list_users():
    users = User.query.all()
    users = [user.user_json() for user in users]
    return json.dumps({'users':users})

# Groups Crud Normal user
@app.route('/api/group', methods=['POST','DELETE','GET'])
@auth.login_required
@roles_accepted('normal_user')
def group():
    if request.method == 'POST':
        try:
            data = request.json

            name = data.get('name')
            description = data.get('description')
            group = Group(name=name, description=description)
            db_session.add(group)
            db_session.flush()
            link = GroupsUsers(group_id = group.id,user_id=g.user.id)
            db_session.add(link)
            db_session.commit()
            return {'msg':'Group created successfully', 'group_id':group.id}
        except:
            return jsonify(msg='Please send data in json')
    elif request.method == 'DELETE':
        try:
            data = request.json
            group_id = data.get('group_id')
            group = Group.query.get(int(group_id))
            link = GroupsUsers.query.filter_by(group_id=group_id).all()

            for i in link:
                db_session.delete(i)
            db_session.delete(group)
            db_session.commit()
            return jsonify(msg='Group deleted successfully')
        except Exception as e:
            print(e)
            return jsonify(msg='Please send data in json')
    else:

        current_user_groups = g.user.groups
        current_user_groups = [group.group_json() for group in current_user_groups]
        return json.dumps(current_user_groups)

@app.route('/api/group/member', methods=['POST','DELETE','GET'])
@auth.login_required
@roles_accepted('normal_user')
def group_member():
    if request.method == 'POST':
        try:
            data =  request.json
            user_list = data.get('user_list')
            group_id = data.get('group_id')
            to_be_inserted = []
            for user_id in user_list:
                to_be_inserted.append(GroupsUsers(group_id=group_id,user_id=user_id))
            db_session.bulk_save_objects(to_be_inserted)
            db_session.commit()
            return jsonify(msg='Users added successfully')
        except:
            return jsonify(msg='Please send data in json')
        # add member
    elif request.method == 'DELETE':
        try:
            data =  request.json
            user_list = data.get('user_list')
            group_id = data.get('group_id')
            user_list = tuple(user_list)
            to_be_deleted = db_session.query(GroupsUsers).filter(GroupsUsers.user_id.in_(user_list)).all()
            for user in to_be_deleted:
                db_session.delete(user)
            db_session.commit()
            return jsonify(msg='Users removed successfully')
        except Exception as e:
            print(e)
            return jsonify(msg='Please send data in json')
    else:
        data =  request.json
        group_id = data.get('group_id')
        users = db_session.query(User).join(GroupsUsers).filter_by(group_id=group_id).all()
        print(users)
        users = [user.user_json() for user in users]
        print(users)
        return json.dumps(users)

@app.route('/group/messages/<group_id>', methods= ['POST','GET'])
@auth.login_required
@roles_accepted('normal_user')
def send_message(group_id):
    if request.method == 'POST':
        try:
            data =  request.json
            message =  data.get('message')
            user_id =  data.get('user_id')
            inserted_message =  Messages(user_id=user_id, group_id= group_id, message=message)
            db_session.add(inserted_message)
            db_session.commit()
            return jsonify(msg='Message sent successfully', message_id=inserted_message.id)
        except:
            return jsonify(msg='Please send data in json')
    else:
        messages = Group.query.get(group_id).messages
        messages = [message.message_json() for message in messages]
        return json.dumps(messages)

@app.route('/group/like_message', methods=['POST'])
@auth.login_required
@roles_accepted('normal_user')
def like_message():
    if request.method == 'POST':
        try:
            data =  request.json
            is_liked = data.get('like_type')
            message_id = data.get('message_id')
            user_id = data.get('user_id')
            like = Likes(user_id=user_id, message_id=message_id, is_liked=bool(is_liked))
            db_session.add(like)
            db_session.commit()
            return jsonify(msg='Like added successfully')
        except Exception as e:
            print(e)
            return jsonify(msg='Please send data in json')

        