FROM debian:8
FROM python:3.5

MAINTAINER Ondrej Sika <ondrej@ondrejsika.com>

RUN apt-get update
RUN apt-get install -y git
RUN git clone https://github.com/slush0/epycyzm.git
RUN pip install cffi

WORKDIR /epycyzm
ENTRYPOINT ./run.sh

