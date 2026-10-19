FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7422

# The host comes from VLAW_HOST, which docker-compose.yml sets explicitly to all interfaces (inside the container the
# published port must reach the server). Without it the server binds loopback, so running this image some other
# way never exposes the unauthenticated API by default.
CMD ["sh", "-c", "exec uvicorn main:app --host ${VLAW_HOST:-127.0.0.1} --port 7422"]
