FROM centos_py3_nginx_flask:1.0
MAINTAINER jicheng.tang

ADD target/movie_site.zip /tmp
RUN unzip /tmp/movie_site.zip -d /movie_site \
    && rm -rf /tmp/movie_site.zip \
    && chmod g+x /movie_site/start.sh \
    && rm -rf /usr/local/nginx/conf/nginx.conf \
    && cp movie_site/nginx.conf /usr/local/nginx/conf/ \
    && cp -r movie_site /usr/local/nginx/html/
#    && rm -rf /movie_site \

WORKDIR /usr/local/nginx/html/movie_site

EXPOSE 80

CMD nginx && bash start.sh