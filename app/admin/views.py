# coding:utf-8

import os
import datetime
from functools import wraps
from flask import render_template, redirect, url_for, flash, session, request, abort
from werkzeug.utils import secure_filename
import uuid

from . import admin
from app.admin.froms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, Oplog, Adminlog, UserLog, Auth, Role
from app import db, app


def admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session['admin_id']
        ).first()
        # 判断是否为超级管理员
        if admin.is_super != 0:
            auths = admin.role.auths
            # auths = list(map(lambda v: int(v), auths.split(',')))
            auths = [int(v) for v in auths.split(',')]
            auth_list = Auth.query.all()
            urls = [v.url for v in auth_list for val in auths if val == v.id]
            rule = str(request.url_rule)
            rule = '/'.join(rule.split('/')[:3])
            # rule = rule.split('/')[:3]
            print(rule)
            if rule not in urls:
                print("auths deny for: {}".format(admin.name))
                abort(404)
        return f(*args, **kwargs)

    return decorated_function


#  上下文管理器
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    return data


#  登录验证装饰器
def admin_login_req(f):
    @wraps(f)
    def decorated_func(*args, **kwargs):
        if not session.get('admin', None):
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kwargs)

    return decorated_func


#  修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)  # 将文件名分割为名称和拓展名
    filename = datetime.datetime.now().strftime('%Y%m%d%H%M%S') + str(uuid.uuid4().hex) + fileinfo[-1]
    # filename = '{datetime}{uuid}{f_tail}'
    return filename


@admin.route('/')
@admin_login_req
def index():
    return render_template('admin/index.html')


@admin.route('/login/', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        # 验证登录有效
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.check_pwd(data['pwd']):
            flash('密码错误', 'err')
            return redirect(url_for('admin.login'))
        # 验证成功后存入会话
        session['admin'] = data['account']
        session['admin_id'] = admin.id
        # 添加登录日志记录
        admin_log = Adminlog(
            admin_id=admin.id,
            ip=request.remote_addr,
        )
        db.session.add(admin_log)
        db.session.commit()
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


@admin.route('/logout/')
@admin_login_req
def logout():
    # 退出后清除会话
    session.pop('admin', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin.login'))


@admin.route('/pwd/', methods=["GET", "POST"])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session['admin']).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash('修改密码成功, 请重新登录！', 'ok')
        return redirect(url_for('admin.logout'))
    return render_template('admin/pwd.html', form=form)


@admin.route('/tag/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        print(form.errors)
        data = form.data
        tag_num = Tag.query.filter_by(name=data['name']).count()
        if tag_num == 1:
            flash('标签名称已经存在！ ', 'err')
            return redirect(url_for('admin.tag_add'))
        tag = Tag(
            name=data['name']
        )
        db.session.add(tag)
        db.session.commit()
        flash('标签添加成功！ ', 'ok')
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason='添加标签: {}'.format(data['name'])
        )
        db.session.add(oplog)
        db.session.commit()
        redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


@admin.route('/tag/del/<int:id_>/', methods=["GET"])
@admin_login_req
@admin_auth
def tag_del(id_=None):
    # tag = Tag.query.get(id)
    tag = Tag.query.filter_by(id=id_).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash("delete success！ ", "ok")
    return redirect(url_for('admin.tag_list', page=1))


@admin.route('/tag/edit/<int:id_>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_edit(id_):
    form = TagForm()
    tag = Tag.query.get_or_404(id_)

    if form.validate_on_submit():
        data = form.data
        tag_num = Tag.query.filter_by(name=data['name']).count()
        if tag.name != data['name'] and tag_num == 1:
            flash('标签名称已经存在！ ', 'err')
            return redirect(url_for('admin.tag_edit', id_=id_))
        tag.name = data['name']
        db.session.add(tag)
        db.session.commit()
        flash('标签修改成功！ ', 'ok')
        redirect(url_for('admin.tag_edit', id_=id_))
    return render_template('admin/tag_edit.html', form=form, tag=tag)


@admin.route('/tag/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def tag_list(page=None):
    if page is None:
        page = 1

    page_data = Tag.query.order_by(
        Tag.addtime.desc()
    ).paginate(page=page, per_page=10)
    for item in page_data.items:
        item.addtime = item.addtime.strftime("%Y-%m-%d %H:%M:%S")
    return render_template('admin/tag_list.html', page_data=page_data)


@admin.route('/move/add', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        file_url = secure_filename(form.url.data.filename)
        file_logo = form.logo.data.filename
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')

        url = change_filename(file_url)
        logo = change_filename(file_logo)
        form.url.data.save(app.config['UP_DIR'] + url)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        move = Movie(
            title=data['title'],
            url=url,
            info=data['info'],
            logo=logo,
            star=int(data['star']),
            playnum=0,
            commentnum=0,
            tag_id=int(data['tag_id']),
            area=data['area'],
            release_time=data['release_time'],
            length=data['length']
        )
        db.session.add(move)
        db.session.commit()
        flash('电影添加成功', 'ok')
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie_add.html', form=form)


@admin.route('/movie/del/<int:id_>/', methods=["GET"])
@admin_login_req
@admin_auth
def movie_del(id_=None):
    movie = Movie.query.get_or_404(int(id_))
    db.session.delete(movie)
    db.session.commit()
    flash("delete movie success！ ", "ok")
    return redirect(url_for('admin.movie_list', page=1))


@admin.route('/move/edit/<int:id_>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def movie_edit(id_=None):
    form = MovieForm()
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(int(id_))
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count == 1 and movie.title != data['title']:
            flash('片名已经存在！', 'err')
            return redirect(url_for('admin.movie_edit', id_=id_))

        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')
        if form.url.data.filename != '':
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config['UP_DIR'] + movie.url)

        if form.logo.data.filename != '':
            file_logo = form.logo.data.filename
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + movie.logo)
        movie.star = data['star']
        movie.tag_id = data['tag_id']
        movie.info = data['info']
        movie.area = data['area']
        movie.length = data['length']
        movie.release_time = data['release_time']
        movie.title = data['title']
        db.session.add(movie)
        db.session.commit()
        flash('电影修改成功', 'ok')
        return redirect(url_for('admin.movie_edit', id_=movie.id))
    return render_template('admin/movie_edit.html', form=form, movie=movie)


@admin.route('/movie/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/movie_list.html', page_data=page_data)


@admin.route('/preview/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        print(data['title'])
        file_logo = form.logo.data.filename
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')
        logo = change_filename(file_logo)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        preview = Preview(
            title=data['title'],
            logo=logo
        )
        db.session.add(preview)
        db.session.commit()
        flash('预告添加成功', 'ok')
        return redirect(url_for('admin.preview_add'))
    return render_template('admin/preview_add.html', form=form)


@admin.route('/preview/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/preview_list.html', page_data=page_data)


@admin.route('/preview/del/<int:id_>/', methods=["GET"])
@admin_login_req
@admin_auth
def preview_del(id_=None):
    preview = Preview.query.get_or_404(int(id_))
    db.session.delete(preview)
    db.session.commit()
    flash("delete preview success！ ", "ok")
    return redirect(url_for('admin.preview_list', page=1))


@admin.route('/preview/edit/<int:id_>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_edit(id_=None):
    form = PreviewForm()
    form.logo.validators = []
    preview = Preview.query.get_or_404(int(id_))
    if request.method == 'GET':
        form.title.data = preview.title

    if form.validate_on_submit():
        data = form.data
        preview_count = Preview.query.filter_by(title=data['title']).count()
        if preview_count == 1 and preview.title != data['title']:
            flash('预告名已经存在！', 'err')
            return redirect(url_for('admin.preview_edit', id_=id_))

        if form.logo.data.filename != '':
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + preview.logo)

        preview.title = data['title']
        db.session.add(preview)
        db.session.commit()
        flash('电影预告修改成功', 'ok')
        return redirect(url_for('admin.preview_edit', id_=preview.id))
    return render_template('admin/preview_edit.html', form=form, preview=preview)


@admin.route('/user/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def user_list(page=None):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        User.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/user_list.html', page_data=page_data)


@admin.route('/user/view/<int:id_>/', methods=['GET'])
@admin_login_req
@admin_auth
def user_view(id_):
    user = User.query.get_or_404(int(id_))
    return render_template('admin/user_view.html', user=user)


@admin.route('/user/del/<int:id_>/', methods=['GET'])
@admin_login_req
@admin_auth
def user_del(id_):
    user = User.query.get_or_404(int(id_))
    db.session.delete(user)
    db.session.commit()
    flash("delete user success！ ", "ok")
    return redirect(url_for('admin.user_list', page=1))


@admin.route('/comment/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def comment_list(page):
    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/comment_list.html', page_data=page_data)


@admin.route('/comment/del/<int:id_>/', methods=['GET'])
@admin_login_req
@admin_auth
def comment_del(id_):
    comment = Comment.query.get_or_404(int(id_))
    db.session.delete(comment)
    db.session.commit()
    flash("delete comment success！ ", "ok")
    return redirect(url_for('admin.comment_list', page=1))


# TODO: 完成电影收藏后端功能
@admin.route('/moviecol/list/')
@admin_login_req
@admin_auth
def moviecol_list():
    return render_template('admin/moviecol_list.html')


@admin.route('/oplog/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def oplog_list(page=None):
    if page is None:
        page = 1
    page_data = Oplog.query.join(
        Admin
    ).filter(
        Admin.id == Oplog.admin_id
    ).order_by(
        Oplog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/oplog_list.html', page_data=page_data)


@admin.route('/adminloginlog/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def adminloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Adminlog.query.join(
        Admin
    ).filter(
        Admin.id == Adminlog.admin_id
    ).order_by(
        Adminlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/adminloginlog_list.html', page_data=page_data)


@admin.route('/userloginlog/list/')
@admin_login_req
@admin_auth
def userloginlog_list():
    return render_template('admin/userloginlog_list.html')


@admin.route('/auth/add/', methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        db.session.add(auth)
        db.session.commit()
        flash('权限添加成功！', 'ok')
    return render_template('admin/auth_add.html', form=form)


@admin.route('/auth/del/<int:id_>/', methods=["GET"])
@admin_login_req
@admin_auth
def auth_del(id_=None):
    auth = Auth.query.filter_by(id=id_).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("delete Auth success！ ", "ok")
    return redirect(url_for('admin.auth_list', page=1))


@admin.route('/auth/edit/<int:id_>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_edit(id_):
    form = AuthForm()
    auth = Auth.query.get_or_404(id_)
    if form.validate_on_submit():
        data = form.data
        # auth_num = Auth.query.filter_by(name=data['name']).count()
        # if auth.name != data['name'] and tag_num == 1:
        #     flash('标签名称已经存在！ ', 'err')
        #     return redirect(url_for('admin.tag_edit', id_=id_))
        auth.name = data['name']
        auth.url = data['url']
        db.session.add(auth)
        db.session.commit()
        flash('权限修改成功！ ', 'ok')
        redirect(url_for('admin.auth_edit', id_=id_))
    return render_template('admin/auth_edit.html', form=form, auth=auth)


@admin.route('/auth/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(
        Auth.addtime.desc()
    ).paginate(page=page, per_page=10)
    for item in page_data.items:
        item.addtime = item.addtime.strftime("%Y-%m-%d %H:%M:%S")
    return render_template('admin/auth_list.html', page_data=page_data)


@admin.route('/role/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role(
            name=data['name'],
            auths=','.join(map(lambda v: str(v), data['auths']))
        )
        db.session.add(role)
        db.session.commit()
        flash('角色添加成功！', 'ok')
    return render_template('admin/role_add.html', form=form)


@admin.route('/role/list/<int:page>/')
@admin_login_req
@admin_auth
def role_list(page):
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        Role.addtime.desc()
    ).paginate(page=page, per_page=10)
    for item in page_data.items:
        item.addtime = item.addtime.strftime("%Y-%m-%d %H:%M:%S")
    return render_template('admin/role_list.html', page_data=page_data)


@admin.route('/role/del/<int:id_>/', methods=["GET"])
@admin_login_req
@admin_auth
def role_del(id_=None):
    role = Role.query.filter_by(id=id_).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash("delete Role success！ ", "ok")
    return redirect(url_for('admin.role_list', page=1))


@admin.route('/role/edit/<int:id_>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_edit(id_):
    form = RoleForm()
    role = Role.query.get_or_404(id_)
    if request.method == 'GET':
        form.auths.data = list(map(lambda x: int(x), role.auths.split(',')))
    if form.validate_on_submit():
        data = form.data
        # auth_num = Auth.query.filter_by(name=data['name']).count()
        # if auth.name != data['name'] and tag_num == 1:
        #     flash('标签名称已经存在！ ', 'err')
        #     return redirect(url_for('admin.tag_edit', id_=id_))
        role.name = data['name']
        role.auths = ','.join(map(lambda v: str(v), data['auths']))
        db.session.add(role)
        db.session.commit()
        flash('角色修改成功！ ', 'ok')
        redirect(url_for('admin.role_edit', id_=id_))
    return render_template('admin/role_edit.html', form=form, role=role)


@admin.route('/admin/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def admin_add():
    form = AdminForm()
    if form.validate_on_submit():
        from werkzeug.security import generate_password_hash
        data = form.data
        admin = Admin(
            name=data['name'],
            pwd=generate_password_hash(data['pwd']),
            role_id=data['role_id']
        )
        db.session.add(admin)
        db.session.commit()
        flash('管理员添加成功！', 'ok')
    return render_template('admin/admin_add.html', form=form)


@admin.route('/admin/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.join(Role).filter(
        Role.id == Admin.role_id
    ).order_by(
        Admin.addtime.desc()
    ).paginate(page=page, per_page=10)
    # for item in page_data.items:
    #     item.addtime = item.addtime.strftime("%Y-%m-%d %H:%M:%S")
    return render_template('admin/admin_list.html', page_data=page_data)
