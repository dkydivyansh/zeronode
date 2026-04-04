from flask import Blueprint, render_template, redirect
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
