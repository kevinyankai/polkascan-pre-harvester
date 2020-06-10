# base image
FROM python:3.6-buster
ENV PYTHONUNBUFFERED 1

# set working directory
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

RUN apk add --no-cache --virtual .build-deps gcc libc-dev git

RUN pip3 install --upgrade pip

# add requirements
COPY ./requirements.txt /usr/src/app/requirements.txt

# install requirements
RUN pip3 install -r requirements.txt

RUN apk del .build-deps gcc libc-dev git

# set timezone
RUN apk add --no-cache tzdata
ENV TZ=Asia/Shanghai

# add app
COPY . /usr/src/app
