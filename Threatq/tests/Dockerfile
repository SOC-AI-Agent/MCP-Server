# The stand-in ThreatQ. Reuses the connector's own dependencies — it needs only
# starlette and uvicorn, both of which are already there.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tests/fake_threatq.py ./tests/fake_threatq.py

RUN useradd --create-home --uid 10003 fake && chown -R fake:fake /app
USER fake

EXPOSE 8500

CMD ["uvicorn", "tests.fake_threatq:app", "--host", "0.0.0.0", "--port", "8500"]
