#!/usr/bin/env python3
from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, current_app
from flask_login import current_user
import requests
import json
from urllib.parse import urlparse
from .models import Agent
main = Blueprint('main', __name__)

REGISTERED_PUB_SERVERS = ['public_loc']
REGISTERED_PRIV_SERVERS = ['private_loc']

TIMEOUT = 10

@main.context_processor
def inject_context():
    ctx = {'servers': REGISTERED_PUB_SERVERS + REGISTERED_PRIV_SERVERS}
    if current_user.is_authenticated:
        ctx.update({'username': current_user.agent_alias,
                   'uid': current_user.id})
    return ctx


# ---------------------------------
# Page Endpoints
# ---------------------------------
@main.route('/')
def index():
    return render_template('index.html')


@main.get('/locations')
def locations():
    return render_template('view_locations.html')


@main.get('/location/add')
def add_location():
    return render_template('add_location.html')


# ---------------------------------
# API Endpoints
# ---------------------------------
@main.get('/api/locations')
def get_locations():
    server_host = request.args.get('server')
    server_url = f"http://{server_host}:4242/location/"
    u = urlparse(server_url)

    if u.hostname not in REGISTERED_PRIV_SERVERS + REGISTERED_PUB_SERVERS:
        flash("Server not supported", "danger")
        return redirect(url_for('main.add_location'))
    if u.hostname in REGISTERED_PRIV_SERVERS:
        server_url += current_user.id

    r = requests.get(server_url, timeout=TIMEOUT)
    return r.json()

@main.post('/api/location/add')
def add_location_post():
    server_host = request.form.get('server')
    loc_json = json.loads(request.form.get('jsonData'))
    if not server_host:
        flash("Select server", "danger")
        return redirect(url_for('main.add_location'))

    server_url = f"http://{server_host}:4242/location/"
    u = urlparse(server_url)

    if u.hostname not in REGISTERED_PRIV_SERVERS + REGISTERED_PUB_SERVERS:
        flash("Server not supported", "danger")
        return redirect(url_for('main.add_location'))
    if u.hostname in REGISTERED_PRIV_SERVERS:
        server_url += current_user.id

    r = requests.post(url=server_url, json=[loc_json], timeout=TIMEOUT)
    timestamp = r.text

    if r.status_code == 201:
        flash("Successfully added location", "info")
        return redirect(url_for('main.locations', timestamp=timestamp,  server=server_host))
    else:
        current_app.logger.error(f"Error adding location. Backend returned with status: {r.status_code}")
        flash(f"Error adding location", "danger")
        return redirect(url_for('main.add_location', server=server_host))

@main.post('/api/share')
def share_locations_post():
    server_host = request.form.get('server')
    receiver = request.form.get('receiver')
    agent = Agent.query.filter_by(id=receiver).first()

    if not agent:
        flash("Select valid agent id for location sharing", "danger")
        return redirect(url_for('main.locations', server=server_host))

    server_url = f"http://{server_host}:4242/share/{current_user.id}?receiver={receiver}"
    u = urlparse(server_url)
    if u.hostname not in REGISTERED_PRIV_SERVERS:
        return Response("Sharing not supported by public servers", status=404)

    r = requests.post(url=server_url, timeout=TIMEOUT)

    if r.status_code == 201:
        flash("Successfully shared location", "info")
        return redirect(url_for('main.locations', server=server_host))
    else:
        flash(f"Error sharing location", "danger")
        return redirect(url_for('main.add_location', server=server_host))

@main.post('/api/location/add/bulk')
def add_bulk_locations():
    server_host = request.form.get('server')
    if not server_host:
        return "Select server", 404

    server_url = f"http://{server_host}:4242/location/"
    u = urlparse(server_url)
    if u.hostname not in REGISTERED_PRIV_SERVERS + REGISTERED_PUB_SERVERS:
        return "Server not supported", 404
    if u.hostname in REGISTERED_PRIV_SERVERS:
        server_url += current_user.id

    loc_json = json.loads(request.form.get('jsonData'))
    r = requests.post(url=server_url, json=loc_json, timeout=TIMEOUT)
    timestamp = r.text

    if r.status_code == 201:
        return "Successfully added locations at timestamp:" + timestamp
    else:
        return "Error adding location", 500
