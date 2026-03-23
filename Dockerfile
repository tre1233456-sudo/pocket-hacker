FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iputils-ping dnsutils whois traceroute curl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["python", "main_run.py"]
