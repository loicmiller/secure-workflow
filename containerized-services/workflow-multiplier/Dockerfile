
FROM python:3.6

COPY . /app

WORKDIR app

RUN pip install -r requirements.txt

RUN apt-get update && apt-get install -y \
    curl

ENTRYPOINT ["python"]

CMD ["server.py"]
