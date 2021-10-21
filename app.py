from flask import Flask, jsonify, abort, request, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from functools import wraps
import jwt
import datetime
import os
import hashlib
import random as rand
import pickle
from typing import *
from flask_sqlalchemy import SQLAlchemy
from flask_selfdoc import Autodoc
import abnex as ab
import re
import importlib.util
import requests
from flask_mail import Mail as flask_mail_mail
app = Flask(__name__)
CORS(app, origins=['https://localhost:5000'])
auto = Autodoc(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/edda/Projects/GIT/Packup/db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Mail:
	@staticmethod
	def msg(subject='', recipients=[], body=''):
		from flask_mail import Message

		return Message(subject=subject, sender=app.config['MAIL_USERNAME'], recipients=recipients, body=body)

	@staticmethod
	def send(message):
		flask_mail_main.send(message)


class List(db.Model):
	id = db.Column(db.Integer, primary_key=True)

	def set_list(self, entry):
		if entry:
			for item in entry:
				self.push(item)

	def s(self):
		return {
			'id': self.id,
			'list': self.list()
		}

	def list(self):
		return [self.get(item.index) for item in ListItem.query.filter_by(parent_id=self.id)]

	def push(self, item):
		new_item = ListItem(item, self.id)
		db.session.add(new_item)
		db.session.commit()

		return self.s()

	def get(self, index):
		item = ListItem.query.filter_by(parent_id=self.id, index=index).first()

		return item.in_type()

	def remove(self, index):
		item = ListItem.query.filter_by(parent_id=self.id, index=index).first()
		db.session.delete(item)
		db.session.commit()


class ListItem(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	index = db.Column(db.Integer)
	item = db.Column(db.LargeBinary)
	parent_id = db.Column(db.Integer)

	def __init__(self, item, parent_id):
		self.item = pickle.dumps(item)
		self.parent_id = parent_id
		self.index = self.get_last_index() + 1

	def s(self):
		return {
			'id': self.id,
			'index': self.index,
			'item': self.in_type(),
			'parent_id': self.parent_id
		}

	def get_last_index(self):
		last_item = ListItem.query.filter_by(parent_id=self.parent_id).order_by(db.desc(ListItem.id)).first()

		if AskLibrary.exists(last_item):
			return last_item.index

		return -1

	def in_type(self):
		return pickle.loads(self.item)


def generic_list_creator(entry: list or None = None):
	generic_list = List()
	db.session.add(generic_list)
	db.session.commit()

	if entry:
		generic_list.set_list(entry)

	return generic_list


class AskLibrary:
	@staticmethod
	def deep(obj, rule):
		rule_key = list(rule.keys())[0]
		rule_val = rule[rule_key]

		for element in obj:
			if str(element[rule_key]) == str(rule_val):
				return element

	@staticmethod
	def quick_set(target, source):
		for key in source.keys():
			if key in target.keys():
				target[key] = source[key]

		return target

	# Deprecated method
	def quickSet(self, target, source):
		return self.quick_set(target, source)

	@staticmethod
	def require_keys(required_keys, _dict):
		statuses = []
		for key in required_keys:
			if key not in _dict:
				statuses.append(False)

			statuses.append(False)

		return False not in statuses

	@staticmethod
	def status(message, code):
		return Response(message, status=code)

	@staticmethod
	def respond(response):
		return jsonify(response)

	@staticmethod
	def get_all_req():
		req = {}
		if request.json:
			for thing in request.json.keys():
				req[thing] = request.json[thing]

		if request.form:
			for thing in request.form.keys():
				req[thing] = request.form[thing]

		if request.args:
			for thing in request.args.keys():
				req[thing] = request.args[thing]

		if request.files:
			for thing in request.files.keys():
				req[thing] = request.files[thing]

		return req

	@staticmethod
	def serialize(db_data):
		return [data.s() for data in db_data]

	@staticmethod
	def exists(query):
		if query is not None:
			result = False
			try:
				result = bool(query.scalar())
			except Exception:
				result = bool(query)
			return result
		return False


class Env:
	@staticmethod
	def get(key):
		return os.environ.get(key)


class Auth:
	def __init__(self):
		import uuid

		self.secret_key = uuid.uuid4().hex
		self.token = jwt.encode({}, self.secret_key)

	def set_token(self, req_token):
		self.token = req_token

	def login(self, user, expiry):
		payload = {
			'user': user,
			'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiry)
		}
		self.encode(payload)

	def encode(self, payload):
		self.token = jwt.encode(payload, str(self.secret_key))

	def decode(self):
		return jwt.decode(self.token, str(self.secret_key))

	def user(self):
		return self.decode()['user']

	def get_token(self):
		return self.token.decode('utf-8')

	def is_valid(self):
		try:
			_ = self.decode()
			return True
		except Exception:
			return False


class Hash:
	@staticmethod
	def hash(to_hash):
		return hashlib.sha256(to_hash.encode('utf-8')).hexdigest()

	@staticmethod
	def check(the_hash, not_hashed_to_check):
		return Hash.hash(not_hashed_to_check) == the_hash


class Random:
	@staticmethod
	def int(start, end, count=1):
		if end - start < count:
			raise ValueError("Integer count greater than the input range!")
		if count > 1:
			return rand.sample(range(start, end), count)

		return rand.randint(start, end)

	@staticmethod
	def __random_float(start, end, decimals):
		return round(rand.uniform(start, end), decimals)

	def float(self, start, end, count=1, decimals=16, unique=False):
		if count <= 1:
			return self.__random_float(start, end, decimals)

		floats = []
		for _ in range(1, count + 1):
			n = self.__random_float(start, end, decimals)
			if unique:
				while n in floats:
					n = self.__random_float(start, end, decimals)
			floats.append(n)

		return floats

	@staticmethod
	def element(iterable, count=1, weights=None, unique=False):
		if unique:
			return rand.sample(iterable, k=count)

		return rand.choices(iterable, weights=weights, k=count)


auth = Auth()
_auth = auth
env = Env()
_env = env
hash = Hash()
_hash = hash
random = Random()
_random = random
mail = Mail()
_mail = mail


def check_for_token(func):
	@wraps(func)
	def wrapped(*args, **kwargs):
		token = request.args.get('token')
		_auth.set_token(token)
		if not token:
			return jsonify({'message': 'Missing token!'}), 400
		try:
			_ = jwt.decode(token, _auth.secret_key)
		except Exception:
			return jsonify({'message': 'Invalid token!'}), 401
		return func(*args, **kwargs)
	return wrapped


limiter = Limiter(app, key_func=get_remote_address)


class Log(db.Model):
	text = db.Column(db.String)
	type = db.Column(db.String)
	origin = db.Column(db.String)
	date_time = db.Column(db.DateTime)
	session = db.Column(db.Integer, autoincrement = True)

	id = db.Column(db.Integer, primary_key=True)

	def __init__(self, text, type, origin, date_time, session):
		self.text = text
		self.type = type
		self.origin = origin
		self.date_time = date_time
		self.session = session
	
	def s(self):
		return {
			'id': self.id,
			'text': self.text,
			'type': self.type,
			'origin': self.origin,
			'date_time': self.date_time,
			'session': self.session,
		}

def add_log(log, type, origin):
	try:
		new_log = Log(log, type, origin, datetime.datetime.now())
		db.session.add(new_log)
		db.session.commit()
	except Exception:
		return 500, None

	return 200, new_log.s()[ 'id']

@app.route('/log/<type>', methods=['post'])
@auto.doc('public')
def post_log__type_(type):
	allowed_types =[ 'debug', 'warning', 'error', 'info']

	if type not in allowed_types:
		abort(Response('Non allowed type. "' + type + '" not in: ' + str(allowed_types), 400))

	if AskLibrary.require_keys([ 'text'], AskLibrary.get_all_req()):
		abort(Response('"text" is required', 400))

	status, id = add_log(AskLibrary.get_all_req()[ 'text'], type, request.remote_addr)

	if id:
		return AskLibrary.respond({'id': id})

	abort(Response(status))

@app.route('/logs', methods=['get'])
@auto.doc('public')
def get_logs():
	return AskLibrary.respond(AskLibrary.serialize(Log.query.all()))

@app.route('/log/<id>', methods=['get'])
@auto.doc('public')
def get_log__id_(id):
	log = Log.query.get(id)
	return AskLibrary.respond(log.s())


@app.route('/docs/', methods=['GET'], defaults={'filter_type': None})
@app.route('/docs/<filter_type>', methods=['GET'])
@auto.doc('public')
def get_docs(filter_type):
	if filter_type:
		return auto.html(filter_type)
	return auto.html(groups=['public', 'private'])


if __name__ == '__main__':
	app.run()
