FROM python:3.11-slim

LABEL maintainer="Pentester"
LABEL description="RETRO-Ollama - Pentesting AI Tool with Local LLM"

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    git \
    nmap \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://ollama.ai/install.sh | sh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV OLLAMA_HOST=http://localhost:11434
ENV DEFAULT_MODEL=llama3.2

EXPOSE 11434

CMD ["python", "main.py"]
