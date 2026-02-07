# Python Image
FROM python:3.10-slim

# Install Tesseract OCR (Zaroori hai OCR ke liye)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Work Directory set karo
WORKDIR /app

# Requirements install karo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code copy karo
COPY . .

# Bot start karo
CMD ["python", "bot.py"]
