# coding:utf-8

from flask import Blueprint, views

admin = Blueprint('admin', __name__)

import app.admin.views
