FROM python:2.7-alpine

RUN apk add --update --no-cache g++ gcc libxslt-dev

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "yarGen.py"]