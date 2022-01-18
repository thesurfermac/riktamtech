import json
import unittest
from requests.auth import HTTPBasicAuth
from main import app
from db import db_session
import base64
from flask import jsonify
from models import User,Role

class AppTest(unittest.TestCase):

  def setUp(self) -> None:
      self.app = app.test_client()
      self.db_session = db_session
  
  def tearDown(self) -> None:
      pass

  def get_admin_token(self):
    email = "abhinav@chat.net"
    password = "adminpass"
    auth = self.encode_token(email, password)
    response = self.app.post('/api/login', headers= {
                'Authorization': f'Basic {auth}'
                })
    return response.json['token']
  
  def get_user_token(self):
    email = "Abhinav-normal1@chat.net"
    password = "normalpass"
    
    auth = self.encode_token(email, password)
    response = self.app.post('/api/login', headers= {
                'Authorization': f'Basic {auth}'
                })
    return response.json['token']

  def encode_token(self, email, password):
    auth = f'{email}:{password}'.encode()
    auth = base64.b64encode(auth).decode('utf-8')
    return auth

  def testInvalidLogin(self):
    email = "dummy@mummy.com"
    password = "password"
    auth = self.encode_token(email, password)
    
    response = self.app.post('/api/login', headers = {
                'Authorization': 'Basic %s' % auth
                })
    self.assertEqual(401, response.status_code)
  
  def testAdminLoginLogout(self):
    email = "abhinav@chat.net"
    password = "adminpass"
    auth = self.encode_token(email, password)
    response = self.app.post('/api/login', headers= {
                'Authorization': f'Basic {auth}'
                })
    self.assertEqual(200, response.status_code)
    self.assertTrue('token' in response.json)
    data = response.json
    token = data['token']
    auth = self.encode_token(token, '')
    response = self.app.get('/api/logout', headers= {
                'Authorization': f'Basic {auth}'
                })
    self.assertEqual(200, response.status_code)
    self.assertTrue('msg' in response.json)


  
  def testUserLoginLogout(self):
    email = "Abhinav-normal1@chat.net"
    password = "normalpass"
    auth = self.encode_token(email, password)
    response = self.app.post('/api/login', headers= {
                'Authorization': f'Basic {auth}'
                })
    
    self.assertEqual(200, response.status_code)
    self.assertTrue('token' in response.json)
    data = response.json
    token = data['token']
    auth = self.encode_token(token, '')
    response = self.app.get('/api/logout', headers= {
                'Authorization': f'Basic {auth}'
                })
    self.assertEqual(200, response.status_code)
    self.assertTrue('msg' in response.json)

  def testIsJson(self):
    token = self.get_admin_token()

    name="Johnson"
    email = "johnson@chat.net"
    password = "normalpass"

    auth = self.encode_token(token, '')
    response = self.app.post('/api/user', headers= {
                'Authorization': f'Basic {auth}'
                }, data=json.dumps({'name':name,'email':email,"password":password}))
    data = response.json
    self.assertEqual(200, response.status_code)
    self.assertEqual(data['msg'], 'Please send data in json')

  def testCreateUserEditUser(self):
    token = self.get_admin_token()

    name="Johnson"
    email = "johnson@chat.net"
    password = "normalpass"
    auth = self.encode_token(token, '')
    response = self.app.post('/api/user', headers= {
                'Authorization': f'Basic {auth}',
                'Content-Type': 'application/json',
                
                }, data=json.dumps({'name':name,'email':email,"password":password}))
    data = response.json
    self.assertEqual(200, response.status_code)
    self.assertEqual(data['msg'], 'User created successfully')
    self.assertTrue('user_id' in data)
    user_id = data['user_id']
    response = self.app.put('/api/user', headers= {
                'Authorization': f'Basic {auth}',
                'Content-Type': 'application/json',
                }, data=json.dumps({'name':'Johnson Anderson','user_id':data['user_id']}))
    data = response.json
    self.assertEqual(200, response.status_code)
    self.assertEqual(data['msg'], 'User edited successfully')
    #cleanup
    user = User.query.get(user_id)
    self.db_session.delete(user)
    self.db_session.commit()

  def testListUser(self):
    # admin user
    token = self.get_admin_token()
    auth = self.encode_token(token, '')
    response = self.app.get('/api/list_users', headers= {
                'Authorization': f'Basic {auth}',
                'Content-Type': 'application/json',
                
                })
    
    data = json.loads(response.data)
    self.assertEqual(200, response.status_code)
    self.assertLess(1,len(data['users']))
    # normal user
    token = self.get_user_token()
    auth = self.encode_token(token, '')
    response = self.app.get('/api/list_users', headers= {
                'Authorization': f'Basic {auth}',
                'Content-Type': 'application/json',
                
                })
    # data = response.data
    data = json.loads(response.data)
    # self.assertEqual(True, False)
    self.assertEqual(200, response.status_code)
    self.assertLess(1,len(data['users']))

  def testGroupCreateDelete(self):
    token = self.get_user_token()
    auth = self.encode_token(token, '')
    response = self.app.post('/api/group', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  }, data=json.dumps({'name':'Group 3','description':"Group description"}))
    data = response.json
    group_id = data['group_id']
    self.assertEqual(data['msg'], 'Group created successfully')
    self.assertEqual(200, response.status_code)


    # list groups
    response = self.app.get('/api/group', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  })
    data = json.loads(response.data)
    self.assertLess(0, len(data))

    # delete groups
    response = self.app.delete('/api/group', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  }, data=json.dumps({'group_id': group_id}))
    print(response.data)
    data = response.json
    self.assertEqual(data['msg'], 'Group deleted successfully')
    self.assertEqual(200, response.status_code)

  def testAddMemberListMemberDeleteMember(self):
    token = self.get_user_token()
    auth = self.encode_token(token, '')
    response = self.app.post('/api/group/member', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  }, data=json.dumps({"group_id":2, "user_list":[3,4,5]}))
    data = response.json
    self.assertEqual(data['msg'], 'Users added successfully')
    self.assertEqual(200, response.status_code)


    # list members
    response = self.app.get('/api/group/member', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  }, data=json.dumps({"group_id":2}))
    data = json.loads(response.data)
    self.assertLess(0, len(data))

    # delete members
    response = self.app.delete('/api/group/member', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  }, data=json.dumps({"group_id":2, "user_list":[3,4,5]}))
    print(response.data)
    data = response.json
    self.assertEqual(data['msg'], 'Users removed successfully')
    self.assertEqual(200, response.status_code)

  def testAddMessages(self):
    token = self.get_user_token()
    auth = self.encode_token(token, '')
    response = self.app.post('/group/messages/2', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  }, data=json.dumps({"message":"Hello world", "user_id":5}))
    data = response.json
    self.assertEqual(data['msg'], 'Message sent successfully')
    self.assertEqual(200, response.status_code)


    # list members
    response = self.app.get('/group/messages/2', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  })
    data = json.loads(response.data)
    self.assertLess(0, len(data))

  def testAddLike(self):
    token = self.get_user_token()
    auth = self.encode_token(token, '')
    response = self.app.post('/group/like_message', headers= {
                  'Authorization': f'Basic {auth}',
                  'Content-Type': 'application/json',
                  }, data=json.dumps({"like_type":"True","message_id":5, "user_id":5}))
    data = response.json
    self.assertEqual(data['msg'], 'Like added successfully')
    self.assertEqual(200, response.status_code)