FROM python:3.8.10
COPY scanner.py ./
RUN pip install click