FROM python:3.8.5-buster

# Directory for the program
WORKDIR /

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy source code
COPY / .

# Run the program
CMD ["python", "src/main.py"]