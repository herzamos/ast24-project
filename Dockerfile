FROM python:latest

WORKDIR /app

RUN apt-get update
RUN apt-get -y install vim

COPY . .

RUN pip install -r requirements.txt

CMD ["bash"]
