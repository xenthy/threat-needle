FROM python:3.8.5-buster

# Directory for the program
WORKDIR /src

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy source code
COPY /src .

# Run the program
CMD ["python", "main.py"]