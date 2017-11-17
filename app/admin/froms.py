# coding:utf-8

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, EqualTo

from app.models import Admin, Tag, Auth, Role

try:
    tags = Tag.query.all()
except Exception as tags_e:
    print(tags_e)
    tags = []
try:
    auth_list = Auth.query.all()
except Exception as auths_e:
    print(auths_e)
    auth_list = []
try:
    role_list = Role.query.all()
except Exception as rolls_e:
    print(rolls_e)
    role_list = []


class LoginForm(FlaskForm):
    account = StringField(
        label='账号',
        validators=[
            DataRequired('Please input id')
        ],
        description='账号',
        render_kw={
            'class': 'form-control',
            'placeholder': 'Please input 账号',
            'required': 'required'
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[
            DataRequired('Please input id')
        ],
        description='密码',
        render_kw={
            'class': 'form-control',
            'placeholder': 'Please input password',
            # 'required': 'required'
        }
    )
    submit = SubmitField(
        label='登录',
        render_kw={
            'class': 'btn btn-primary btn-block btn-flat'
        }
    )

    def validate_account(self, field):
        account = field.data
        admin = Admin.query.filter_by(name=account).count()
        if admin == 0:
            raise ValidationError('账号不存在! ')


class TagForm(FlaskForm):
    name = StringField(
        label='标签',
        validators=[
            DataRequired('请输入标签! ')
        ],
        description='标签',
        render_kw={
            'class': 'form-control',
            'id': 'input_name',
            'placeholder': "请输入标签名称！",
            # 'required': 'required'
        }
    )
    submit = SubmitField(
        label='确认',
        render_kw={
            'class': 'btn btn-primary'
        }
    )


class MovieForm(FlaskForm):
    title = StringField(
        label="片名",
        validators=[
            DataRequired('请输入片名')
        ],
        description='片名',
        render_kw={
            'class': 'form-control',
            'id': 'input_title',
            'placeholder': "请输入片名！",
            # 'required': 'required'
        }
    )
    url = FileField(
        label="文件",
        validators=[
            DataRequired('请上传文件')
        ],
        description='文件',
    )
    info = TextAreaField(
        label="简介",
        validators=[
            DataRequired('请输入简介')
        ],
        description='简介',
        render_kw={
            'class': 'form-control',
            'row': 10
        }
    )
    logo = FileField(
        label="封面",
        validators=[
            DataRequired('请上传封面')
        ],
        description='封面',
    )
    star = SelectField(
        label="星级",
        validators=[
            DataRequired('请选择星级')
        ],
        coerce=int,
        choices=[(1, '1星'), (2, '2星'), (3, '3星'), (4, '4星'), (5, '5星')],
        description='星级',
        render_kw={
            'class': 'form-control',
        }
    )
    tag_id = SelectField(
        label="标签",
        validators=[
            DataRequired('请选择标签')
        ],
        coerce=int,
        choices=[(v.id, v.name) for v in tags],
        description='标签',
        render_kw={
            'class': 'form-control',
        }
    )
    area = StringField(
        label="地区",
        validators=[
            DataRequired('请输入地区')
        ],
        description='地区',
        render_kw={
            'class': 'form-control',
            'placeholder': "请输入地区！",
            # 'required': 'required'
        }
    )
    length = StringField(
        label="片长",
        validators=[
            DataRequired('请输入片长')
        ],
        description='片长',
        render_kw={
            'class': 'form-control',
            'placeholder': "请输入片长！",
        }
    )
    release_time = StringField(
        label="上映时间",
        validators=[
            DataRequired('请输入上映时间')
        ],
        description='上映时间',
        render_kw={
            'class': 'form-control',
            'placeholder': "请输入上映时间！",
            'id': 'input_release_time'
            # 'required': 'required'
        }
    )
    submit = SubmitField(
        label='确认',
        render_kw={
            'class': 'btn btn-primary'
        }
    )


class PreviewForm(FlaskForm):
    title = StringField(
        label="预告标题",
        validators=[
            DataRequired('请输入预告标题')
        ],
        description='预告标题',
        render_kw={
            'class': 'form-control',
            'id': 'input_title',
            'placeholder': "请输入预告标题！",
            'required': 'required'
        }
    )
    logo = FileField(
        label="预告封面",
        validators=[
            DataRequired('请上传预告封面')
        ],
        description='预告封面',
    )
    submit = SubmitField(
        label='确认',
        render_kw={
            'class': 'btn btn-primary'
        }
    )


class PwdForm(FlaskForm):
    old_pwd = PasswordField(
        label='old password',
        validators=[
            DataRequired('please input old password!')
        ],
        description='old_password',
        render_kw={
            'class': 'form-control',
            'placeholder': 'please input old pwd!'
        }
    )
    new_pwd = PasswordField(
        label='new password',
        validators=[
            DataRequired('please input new password!')
        ],
        description='new_password',
        render_kw={
            'class': 'form-control',
            'placeholder': 'please input new pwd!'
        }
    )
    submit = SubmitField(
        label='确认',
        render_kw={
            'class': 'btn btn-primary'
        }
    )

    def validate_old_pwd(self, field):
        from flask import session

        pwd = field.data
        name = session['admin']
        admin = Admin.query.filter_by(
            name=name
        ).first()
        if not admin.check_pwd(pwd):
            raise ValidationError('old password wrong!')


class AuthForm(FlaskForm):
    name = StringField(
        label='权限名称',
        validators=[
            DataRequired('请输入权限名称')
        ],
        description='权限名称',
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "请输入权限"

        }
    )
    url = StringField(
        label='权限地址',
        validators=[
            DataRequired('请输入权限地址')
        ],
        description='权限地址',
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "请输入权限地址"

        }
    )
    submit = SubmitField(
        label='确认',
        render_kw={
            'class': 'btn btn-primary'
        }
    )


class RoleForm(FlaskForm):
    name = StringField(
        label='角色名称',
        validators=[
            DataRequired('请输入角色名称')
        ],
        description='角色名称',
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "请输入角色名称"

        }

    )
    auths = SelectMultipleField(
        label='权限列表',
        validators=[
            DataRequired('请选择权限！')
        ],
        coerce=int,
        choices=[(v.id, v.name) for v in auth_list],
        description='权限列表',
        render_kw={
            "class": "form-control",
            # "placeholder": "请选择权限"
        }
    )
    submit = SubmitField(
        label='确认',
        render_kw={
            'class': 'btn btn-primary'
        }
    )


class AdminForm(FlaskForm):
    name = StringField(
        label='管理员名称',
        validators=[
            DataRequired('Please input Admin Name!')
        ],
        description='管理员名称',
        render_kw={
            'class': 'form-control',
            'placeholder': 'Please input Admin Name.',
            'required': 'required'
        }
    )
    pwd = PasswordField(
        label='管理员密码',
        validators=[
            DataRequired('Please input Admin Password!')
        ],
        description='管理员密码',
        render_kw={
            'class': 'form-control',
            'placeholder': 'Please input Admin password.',
            'required': 'required'
        }
    )
    repwd = PasswordField(
        label='重复密码',
        validators=[
            DataRequired('Please reinput password!'),
            EqualTo('pwd', message='密码不一致！')
        ],
        description='重复密码',
        render_kw={
            'class': 'form-control',
            'placeholder': 'Please reinput password.',
            'required': 'required'
        }
    )
    role_id = SelectField(
        label='所属角色',
        coerce=int,
        choices=[(v.id, v.name) for v in role_list],
        render_kw={
            'class': 'form-control',
        }
    )
    submit = SubmitField(
        label='确认',
        render_kw={
            'class': 'btn btn-primary btn-block btn-flat'
        }
    )

    def validate_account(self, field):
        account = field.data
        admin = Admin.query.filter_by(name=account).count()
        if admin == 0:
            raise ValidationError('账号不存在! ')
