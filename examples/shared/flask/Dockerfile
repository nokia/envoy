FROM python:3.10.5-slim-bullseye@sha256:c42123784920092f8156cefdeec0106045a32db47e55c521447aa76cd062386a

ADD requirements.txt /tmp/flask-requirements.txt
RUN pip3 install -qr /tmp/flask-requirements.txt
RUN mkdir /code

ENTRYPOINT ["python3", "/code/service.py"]
