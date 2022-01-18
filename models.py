from db import Base
import config
from flask_security import UserMixin, RoleMixin
from sqlalchemy.orm import relationship, backref
from sqlalchemy import Boolean, DateTime, Column, Integer, \
                       String, ForeignKey
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy.sql import func

class RolesUsers(Base):
    __tablename__ = 'roles_users'
    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    role_id = Column('role_id', Integer(), ForeignKey('role.id'))

class Role(Base, RoleMixin):
    __tablename__ = 'role'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    description = Column(String(255))

class User(Base, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    username = Column(String(255))
    password = Column(String(255))
    active = Column(Boolean())
    created_time = Column(DateTime(timezone=True), server_default=func.now())
    roles = relationship('Role', secondary='roles_users',
                         backref=backref('users', lazy='dynamic'))
    groups = relationship('Group',secondary='groups_users', 
                         backref=backref('users', lazy='dynamic'))
    
    def has_role(self, role):
        return super().has_role(role)

    def hash_password(self, password):
        print(pwd_context.encrypt(password), password)
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def generate_auth_token(self, expiration=600):
      s = Serializer(config.SECRET_KEY, expires_in = expiration)
      roles = [role.name for role in self.roles]
      return s.dumps({ 'id': self.id, 'roles': roles })


    @staticmethod
    def verify_auth_token(token):
        s = Serializer(config.SECRET_KEY)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token

        user = User.query.get(data['id'])
        return user
    
    def user_json(self):
      return dict(name=self.username, user_id=self.id, email=self.email)

class TokenBlackList(Base):
  __tablename__ = "token_blacklist"
  id = Column(Integer, primary_key=True)
  user_id = Column('user_id', Integer(), ForeignKey('user.id'))
  blacklisted_token =  Column('token', String(1000))
  created_time = Column(DateTime(timezone=True), server_default=func.now())

class Group(Base):
  __tablename__ = 'group'
  id = Column(Integer, primary_key=True)
  name = Column(String(80), unique=True)
  description = Column(String(255))
  created_time = Column(DateTime(timezone=True), server_default=func.now())
  messages = relationship('Messages')

  def group_json(self):
      return dict(name=self.name, group_id=self.id, email=self.description)

class GroupsUsers(Base):
  __tablename__ = 'groups_users'
  id = Column(Integer, primary_key=True)
  user_id = Column('user_id', Integer(), ForeignKey('user.id'))
  group_id = Column('group_id', Integer(), ForeignKey('group.id'))
  created_time = Column(DateTime(timezone=True), server_default=func.now())


class Messages(Base):
  __tablename__ = "group_messages"
  id = Column(Integer, primary_key=True)
  user_id = Column('user_id', Integer(), ForeignKey('user.id'))
  group_id = Column('group_id', Integer(), ForeignKey('group.id'))
  message = Column(String(150))
  created_time = Column(DateTime(timezone=True), server_default=func.now())

  def message_json(self):
      return dict(message=self.message, user_id=self.user_id)

class Likes(Base):
  __tablename__ = "message_likes"
  id = Column(Integer, primary_key=True)
  user_id = Column('user_id', Integer(), ForeignKey('user.id'))
  message_id = Column('group_id', Integer(), ForeignKey('group_messages.id'))
  is_liked = Column(Boolean(), default=False)
  created_time = Column(DateTime(timezone=True), server_default=func.now())