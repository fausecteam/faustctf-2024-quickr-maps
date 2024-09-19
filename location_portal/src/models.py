#!/usr/bin/env python3
from . import db
from flask_login import UserMixin


class Agent(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True)
    agent_alias = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
