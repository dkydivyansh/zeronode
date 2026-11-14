from flask import Blueprint, render_template, redirect, send_from_directory, jsonify, current_app, make_response
from app.routes.auth import get_current_user

client_bp = Blueprint('client', __name__, template_folder='../templates')

@client_bp.route('/')
def index():
    user = get_current_user()
    return render_template('view/index.html', user=user)

@client_bp.route('/login')
def login():
    user = get_current_user()
    if user:
        return redirect('/app/home')
    return render_template('view/login.html')

@client_bp.route('/dash')
def dash_shortcut():
    """Shortcut redirect to dashboard."""
    return redirect('/app/home')

@client_bp.route('/manifest.json')
def manifest():
    """Serve PWA Web App Manifest with correct MIME type."""
    response = make_response(send_from_directory(current_app.static_folder, 'manifest.json', mimetype='application/manifest+json'))
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

@client_bp.route('/sw.js')
def service_worker():
    """Serve root-scoped Service Worker with bypass headers."""
    response = make_response(send_from_directory(current_app.static_folder, 'sw.js', mimetype='application/javascript'))
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@client_bp.route('/offline')
def offline():
    """Offline fallback page for PWA."""
    return render_template('view/offline.html')

@client_bp.route('/api/version')
def api_version():
    """Version endpoint for Service Worker and PWA updater."""
    return jsonify({
        "status": "success",
        "version": "1.1.0",
        "build": "20261114.pwa",
        "name": "ZeroNode"
    })

