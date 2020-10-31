ifeq ($(OS),Windows_NT)
	CC=python
else
	CC=sudo python3
endif

PFLAGS=-3.8-64

TARGET?=src/main
SOURCES:=$(wildcard src/*.py)

.PHONY: all check clean

all:
	$(CC) $(TARGET).py

check:
	python -m py_compile $(SOURCES)

doc:
	sudo docker build -t threat_needle:latest .
	sudo docker run --network host -ti threat_needle

docclean:
	sudo docker system prune -a

clean:
ifeq ($(OS),Windows_NT)
	@powershell "(Get-ChildItem * -Include *.pyc -Recurse | Remove-Item)"
	@powershell "(Get-ChildItem * -Include *.cap -Recurse | Remove-Item)"
	@powershell "(Get-Item ./.cache/* -exclude placeholder | Remove-Item -Recurse)"
	@echo Cleaned up .pyc, .cap files and .cache files
else
	@echo "Cleaning up [.pyc, .cap, .cache, carved] files..."
	@sudo find . -type f -name "*.pyc" -delete
	@sudo find . -type f -name "*.cap" -delete
	@sudo find ./.cache/* -type f,d -not -name 'placeholder' -delete
	@sudo find ./carved/* -type f,d -not -name 'placeholder' -delete
	@echo "Cleaning complete!"
endif
