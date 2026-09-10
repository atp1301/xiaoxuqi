FROM python:3.12-slim
WORKDIR /app
COPY server.py constants.py flag.txt ./
USER 65532:65532
EXPOSE 8088
CMD ["python", "/app/server.py", "gateway", "--host", "0.0.0.0", "--port", "8088"]
