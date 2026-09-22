FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Nothing here needs root, and this container talks to Splunk.
RUN useradd --create-home --uid 10001 mcp && chown -R mcp:mcp /app
USER mcp

EXPOSE 8200

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8200"]
