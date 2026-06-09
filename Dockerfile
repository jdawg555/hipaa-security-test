FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir ".[aws,github,identity,serve]"
WORKDIR /workspace
EXPOSE 8787
CMD ["hipaa-audit", "serve", "/workspace", "--host", "0.0.0.0", "--port", "8787", "--no-browser"]
