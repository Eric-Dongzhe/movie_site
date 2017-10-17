from . import home


@home.route('/')
def index():
    # return "<h1 style='color:green'> this is home</h1>"
    return "<h1 style='color:green'>欢欢同学你要好好学git</h1>"
