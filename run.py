from app import create_app
import os

# Load .env file manually so run.py sees FLASK_ENV before app creation
_env_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.isfile(_env_path):
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, val = line.partition('=')
                os.environ.setdefault(key.strip(), val.strip())

env = os.environ.get('FLASK_ENV', 'dev')
app = create_app(env)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8862))
    if env in ['production', 'prod']:
        print(f"[*] Starting Production WSGI Server (Waitress) on 0.0.0.0:{port}...")
        from waitress import serve
        serve(app, host='0.0.0.0', port=port)
    else:
        print(f"[*] Starting Development Server on 127.0.0.1:{port}...")
        app.run(host='127.0.0.1', port=port, debug=True)