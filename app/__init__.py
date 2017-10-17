from flask import Flask


# app = Flask(__name__)
# app.debub = True

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app = Flask(__name__)
app.debub = True

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix='/admin')
