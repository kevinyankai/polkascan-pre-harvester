# base image
FROM python:3.8-buster
ENV PYTHONUNBUFFERED 1

# set working directory
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

RUN pip3 install --upgrade pip

# add requirements
COPY ./requirements.txt /usr/src/app/requirements.txt

# install requirements
RUN pip3 install -r requirements.txt

# Set timezone
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN dpkg-reconfigure -f noninteractive tzdata

# add app
COPY . /usr/src/app
