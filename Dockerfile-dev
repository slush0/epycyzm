FROM python:3.5

MAINTAINER Ondrej Sika <ondrej@ondrejsika.com>

RUN pip install cffi

WORKDIR /epycyzm

ENTRYPOINT ["./run.sh"]
CMD ["stratum+tcp://slush:x@zec.slushpool.com:4444"]

