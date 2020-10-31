FROM python:3.8.5

# Directory for the program
WORKDIR /

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy source code
COPY / .

EXPOSE 8000

# Run the program
CMD ["python", "src/main.py"]
