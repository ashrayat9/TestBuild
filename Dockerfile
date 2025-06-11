###########
# BUILDER #
###########

# pull official base image
FROM python:3.10.9-alpine as builder

# set work directory
WORKDIR /app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

######################################################################################################################## 
                                                #Setting up PSE Requirements
######################################################################################################################## 
COPY pse.crt /usr/local/share/ca-certificates/pse.crt
RUN update-ca-certificates

ARG ir_proxy
ARG host_ip
ARG SCAN_ID
ENV http_proxy=${ir_proxy}
ENV https_proxy=${ir_proxy}
ENV HTTP_PROXY=${ir_proxy}
ENV HTTPS_PROXY=${ir_proxy}
RUN echo "Value of https_proxy: $https_proxy"
# For pip specifically, you might also need:
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

######################################################################################################################## 
######################################################################################################################## 

RUN apk update 
RUN apk upgrade 
RUN apk add postgresql-dev gcc python3-dev musl-dev

# install dependencies

RUN pip install --upgrade pip && apk add --no-cache --virtual .build-deps build-base curl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --upgrade pip