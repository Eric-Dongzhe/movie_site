import os

from flask import Flask
from flask import render_template
from flask_sqlalchemy import SQLAlchemy


# from app.home import home as home_blueprint
# from app.admin import admin as admin_blueprint

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] ='mysql+pymysql://root:spider04@spider04.wmcloud-dev.com/moviesite?charset=utf8'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moviesite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'djiaofo45dfafe4das87f'
app.config['UP_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/uploads/')
app.debug = True
db = SQLAlchemy(app)

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix='/admin')


@app.errorhandler(404)
def page_not_fund(error):
    return render_template('home/404.html'), 404
