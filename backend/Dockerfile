FROM python:3.9

RUN mkdir /code
WORKDIR /code

COPY . .
RUN pip install -r requirements.dev.txt

CMD ./manage.py wait_for_db && ./manage.py migrate && ./manage.py createcachetable && celery -A backend worker --loglevel WARNING -D && gunicorn -b 0.0.0.0:3000 backend.asgi -k uvicorn.workers.UvicornWorker
