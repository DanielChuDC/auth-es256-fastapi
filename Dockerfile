FROM tiangolo/uvicorn-gunicorn:python3.9-slim

LABEL maintainer="danielchu"

ENV WORKERS_PER_CORE=4 
ENV MAX_WORKERS=24
ENV LOG_LEVEL="warning"
ENV TIMEOUT="200"

RUN mkdir /auth

COPY requirements.txt /auth

WORKDIR /auth

RUN pip install -r requirements.txt

COPY . /auth

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]