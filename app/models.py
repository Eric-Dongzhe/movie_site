# coding:utf-8
from datetime import datetime
from app import db

# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
# #
# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:spider04@spider04.wmcloud-dev.com/moviesite?charset=utf8'
# # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///moviesite.db'
# #
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# #
# db = SQLAlchemy(app)


# User
class User(db.Model):
    __tablename__ = 'user'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    pwd = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(11), unique=True)
    info = db.Column(db.Text)
    face = db.Column(db.String(255))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)
    uuid = db.Column(db.String(255), unique=True)

    userlogs = db.relationship('UserLog', backref='user')  # UserLog foreingKye
    comments = db.relationship('Comment', backref='user')
    moviecols = db.relationship('Moviecol', backref='user')

    def __repr__(self):
        return '<User {}>'.format(self.name)


# UserLog
class UserLog(db.Model):
    __tablename__ = 'userlog'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<UserLog {}>'.format(self.name)


class Tag(db.Model):
    __tablename__ = 'tag'
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    movies = db.relationship('Movie', backref='tag')  # movie foreign key

    def __repr__(self):
        return '<Tag {}>'.format(self.name)


class Movie(db.Model):
    __tablename__ = 'movie'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), unique=True)
    url = db.Column(db.String(255), unique=True)
    info = db.Column(db.Text)
    logo = db.Column(db.String(255), unique=True)
    star = db.Column(db.SmallInteger)
    playnum = db.Column(db.BigInteger)
    commentnum = db.Column(db.BigInteger)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'))  # tag foreign key
    area = db.Column(db.String(255))
    release_time = db.Column(db.Date)
    length = db.Column(db.String(100))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    comments = db.relationship('Comment', backref='movie')
    moviecols = db.relationship('Moviecol', backref='movie')

    def __repr__(self):
        return '<Movie {}>'.format(self.name)


class Preview(db.Model):
    __tablename__ = 'preview'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), unique=True)
    logo = db.Column(db.String(255), unique=True)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<Preview {}>'.format(self.title)


class Comment(db.Model):
    __tablename__ = 'comment'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<Comment {}>'.format(self.id)


class Moviecol(db.Model):
    """
    movie collections
    """
    __tablename__ = 'moviecol'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<Moviecol {}>'.format(self.id)


class Auth(db.Model):
    __tablename__ = 'auth'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    url = db.Column(db.String(255), unique=True)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<Auth {}>'.format(self.name)


class Role(db.Model):
    __tablename__ = 'role'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    auths = db.Column(db.String(600))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<Role {}>'.format(self.name)


class Admin(db.Model):
    """
    管理员
    """
    __tablename__ = 'admin'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    pwd = db.Column(db.String(100))
    is_super = db.Column(db.SmallInteger)  # 0 is super
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    adminlogs = db.relationship('Adminlog', backref='admin')
    oplogs = db.relationship('Oplog', backref='admin')

    # email = db.Column(db.String(100), unique=True)
    # phone = db.Column(db.String(11), unique=True)
    # info = db.Column(db.Text)
    # face = db.Column(db.String(255))
    # uuid = db.Column(db.String(255), unique=True)

    def __repr__(self):
        return '<Admin {}>'.format(self.name)

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


class Adminlog(db.Model):
    __tablename__ = 'adminlog'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<AdminLog {}>'.format(self.name)


class Oplog(db.Model):
    __tablename__ = 'oplog'
    __table_args__ = {"useexisting": True}

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))
    reason = db.Column(db.String(600))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<OpLog {}>'.format(self.name)


def insert_user():
    from werkzeug.security import generate_password_hash

    for i in range(1, 20):
        name = "user_{}".format(i)
        pwd = "pwd_{}".format(i)
        email = '66666{}@dell.com'.format(i)
        phone = '66666{}'.format(i)
        info = '大家好！我是第{}号会员'.format(i)

        user = User(
            name=name,
            pwd=generate_password_hash(pwd),
            email=email,
            phone=phone,
            info=info
        )
        db.session.add(user)
    db.session.commit()


def insert_coment():
    from random import choice
    comments = ['无聊', '屌炸天', '女主好漂亮！！！有木有', '不后悔', '女主是谁', '给小萝莉打call', '楼上的，打你妹的call']
    for i in range(3, 20):
        comment = Comment(
            content=choice(comments),
            movie_id=choice([2,3]),
            user_id=i
        )
        print(comment)
        db.session.add(comment)
    db.session.commit()

if __name__ == '__main__':
    # db.create_all()

    # role = Role(
    #     name='超级管理员',
    #     auths = '很牛逼'
    #
    # )
    # db.session.add(role)
    # db.session.commit()


    # from werkzeug.security import generate_password_hash
    # # #
    # admin = Admin(
    #     name='aaaa',
    #     pwd=generate_password_hash("123456d"),
    #     is_super=0,
    #     role_id=1
    # )
    # db.session.add(admin)
    # db.session.commit()
    # insert_user()

    insert_coment()
    pass
