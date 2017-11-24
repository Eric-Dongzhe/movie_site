# coding:utf-8
from flask_script import Manager
from app import app

if __name__ == '__main__':
    # app.run()
    # app.run(host="0.0.0.0", port=5000, threaded=True)
    manager = Manager(app)
    manager.run()
