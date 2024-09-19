#!/usr/bin/env python3
from flask import Blueprint, redirect, url_for, render_template, request, flash
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import Agent
import uuid

auth = Blueprint('auth', __name__)

@auth.get('/login')
def login():
    return render_template('login.html')

@auth.post('/login')
def login_post():

    agent_alias = request.form.get('agent_alias')
    password = request.form.get('password')
    agent = Agent.query.filter_by(agent_alias=agent_alias).first()

    if not agent or not check_password_hash(agent.password, password):
        flash('Try again.', 'danger')
        return redirect(url_for('auth.login'))

    print(login_user(agent))
    return redirect(url_for('main.index'))

@auth.get('/register')
def register():
    return render_template('register.html')

@auth.post('/register')
def register_post():
    agent_alias = request.form.get('agent_alias')
    password = request.form.get('password')

    agent = Agent.query.filter_by(agent_alias=agent_alias).first()

    if agent:
        flash('Agent with alias already exists!', 'danger')
        return redirect(url_for('auth.register'))

    new_agent = Agent(id=str(uuid.uuid4()), agent_alias=agent_alias, password=generate_password_hash(password, method='pbkdf2:sha256'))

    db.session.add(new_agent)
    db.session.commit()

    flash('Registered new agent', 'info')
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
