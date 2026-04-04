from app import create_app
import os
env = os.environ.get('FLASK_ENV', 'dev')
app = create_app(env)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
