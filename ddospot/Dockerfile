FROM alpine:edge
MAINTAINER aelth aelthegrin@gmail.com

# Install prerequisites
RUN apk --update --no-cache add python3 python3-dev build-base libcap py3-pip git

# Add new user and group under which ddospot will run
RUN addgroup -g 1000 ddospot 
RUN adduser -D -s /sbin/nologin -u 1000 -G ddospot ddospot 

# Create DDoSPot directory and copy source
COPY . /ddospot

# Install python requirements
RUN pip3 install --upgrade pip
RUN pip3 install -r /ddospot/requirements.txt

# Fix permissions
RUN chown ddospot.ddospot -R /ddospot/*

# Enable capabilities on python interpreter in virtualenv in order to enable unprivileged user to bind on privileged ports
#RUN setcap 'cap_net_bind_service=+ep' env/bin/python

# Expose relevant udp port
EXPOSE 19/udp 53/udp 123/udp 161/udp 1900/udp

# Start DDoSPot
USER ddospot
WORKDIR /ddospot
CMD ["python3", "ddospot.py", "-n"]
