#!/bin/bash
echo "Starting"
echo "Nginx Startup completed"

nohup python manage.py runserver -h 127.0.0.1 -p 5001 &
nohup python manage.py runserver -h 127.0.0.1 -p 5002 &
nohup python manage.py runserver -h 127.0.0.1 -p 5003 &
python manage.py runserver -h 127.0.0.1 -p 5004
echo "Startup completed"