FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
USER 65532:65532
EXPOSE 8088
CMD ["python", "/app/app.py", "--host", "0.0.0.0", "--port", "8088"]
