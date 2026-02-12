FROM python:3.11-alpine

WORKDIR /app

COPY /dist/flaskr-1.0.0-py2.py3-none-any.whl ./dist/

RUN pip install ./dist/flaskr-1.0.0-py2.py3-none-any.whl
RUN pip install waitress
RUN flask --app flaskr init-db


ENV FLASK_APP=__init__.py
ENV FLASK_ENV=development

EXPOSE 8080

CMD ["waitress-serve", "--call", "flaskr:create_app"]
