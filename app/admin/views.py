import os

from . import admin
from flask import render_template, redirect, url_for, flash, session, request
from app.admin.froms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol
from functools import wraps
from app import db, app
from werkzeug.utils import secure_filename
import uuid
import datetime


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
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.check_pwd(data['pwd']):
            flash('密码错误', 'err')
            return redirect(url_for('admin.login'))
        # 验证成功后存入会话
        session['admin'] = data['account']
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


@admin.route('/logout/')
@admin_login_req
def logout():
    # 退出后清除会话
    session.pop('account', None)
    return redirect(url_for('admin.login'))


@admin.route('/pwd/', methods=["GET", "POST"])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session['admin']).first()
        print(admin)
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash('修改密码成功, 请重新登录！', 'ok')
        return redirect(url_for('admin.logout'))
    return render_template('admin/pwd.html', form=form)


@admin.route('/tag/add', methods=["GET", "POST"])
@admin_login_req
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
        redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


@admin.route('/tag/del/<int:id_>/', methods=["GET"])
@admin_login_req
def tag_del(id_=None):
    # tag = Tag.query.get(id)
    tag = Tag.query.filter_by(id=id_).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash("delete success！ ", "ok")
    return redirect(url_for('admin.tag_list', page=1))


@admin.route('/tag/edit/<int:id_>', methods=["GET", "POST"])
@admin_login_req
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
def movie_del(id_=None):
    movie = Movie.query.get_or_404(int(id_))
    db.session.delete(movie)
    db.session.commit()
    flash("delete movie success！ ", "ok")
    return redirect(url_for('admin.movie_list', page=1))


@admin.route('/move/edit<int:id_>/', methods=["GET", "POST"])
@admin_login_req
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


@admin.route('/movie/list<int:page>/', methods=["GET"])
@admin_login_req
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/movie_list.html', page_data=page_data)


@admin.route('/preview/add', methods=["GET", "POST"])
@admin_login_req
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


@admin.route('/preview/list<int:page>/', methods=["GET"])
@admin_login_req
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/preview_list.html', page_data=page_data)


@admin.route('/preview/del/<int:id_>/', methods=["GET"])
@admin_login_req
def preview_del(id_=None):
    preview = Preview.query.get_or_404(int(id_))
    db.session.delete(preview)
    db.session.commit()
    flash("delete preview success！ ", "ok")
    return redirect(url_for('admin.preview_list', page=1))


@admin.route('/preview/edit<int:id_>/', methods=["GET", "POST"])
@admin_login_req
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


@admin.route('/user/list<int:page>', methods=["GET"])
@admin_login_req
def user_list(page=None):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        User.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/user_list.html', page_data=page_data)


@admin.route('/user/view<int:id_>', methods=['GET'])
@admin_login_req
def user_view(id_):
    user = User.query.get_or_404(int(id_))
    return render_template('admin/user_view.html', user=user)


@admin.route('/user/del<int:id_>', methods=['GET'])
@admin_login_req
def user_del(id_):
    user = User.query.get_or_404(int(id_))
    db.session.delete(user)
    db.session.commit()
    flash("delete user success！ ", "ok")
    return redirect(url_for('admin.user_list', page=1))


@admin.route('/comment/list<int:page>', methods=['GET'])
@admin_login_req
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


@admin.route('/comment/del<int:id_>', methods=['GET'])
@admin_login_req
def comment_del(id_):
    comment = Comment.query.get_or_404(int(id_))
    db.session.delete(comment)
    db.session.commit()
    flash("delete comment success！ ", "ok")
    return redirect(url_for('admin.comment_list', page=1))


@admin.route('/moviecol/list')
@admin_login_req
def moviecol_list():
    return render_template('admin/moviecol_list.html')


@admin.route('/oplog/list')
@admin_login_req
def oplog_list():
    return render_template('admin/oplog_list.html')


@admin.route('/adminloginlog/list')
@admin_login_req
def adminloginlog_list():
    return render_template('admin/adminloginlog_list.html')


@admin.route('/userloginlog/list')
@admin_login_req
def userloginlog_list():
    return render_template('admin/userloginlog_list.html')


@admin.route('/auth/add')
@admin_login_req
def auth_add():
    return render_template('admin/auth_add.html')


@admin.route('/auth/list')
@admin_login_req
def auth_list():
    return render_template('admin/auth_list.html')


@admin.route('/role/add')
@admin_login_req
def role_add():
    return render_template('admin/role_add.html')


@admin.route('/role/list')
@admin_login_req
def role_list():
    return render_template('admin/role_list.html')


@admin.route('/admin/add')
@admin_login_req
def admin_add():
    return render_template('admin/admin_add.html')


@admin.route('/admin/list')
@admin_login_req
def admin_list():
    return render_template('admin/admin_list.html')
