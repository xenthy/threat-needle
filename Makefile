ifeq ($(OS),Windows_NT)
	CC=python
else
	CC=sudo python3
endif

PFLAGS=-3.8-64

TARGET?=src/main
CHECK?=src/check
SOURCES:=$(wildcard src/*.py)

.PHONY: all check clean

all:
	$(CC) $(TARGET).py

check:
	$(CC) $(CHECK).py

clean:
ifeq ($(OS),Windows_NT)
	@powershell "(Get-ChildItem * -Include *.pyc -Recurse | Remove-Item)"
	@powershell "(Get-ChildItem * -Include *.cap -Recurse | Remove-Item)"
	@echo Cleaned up .pyc, .cap files and .cache files
else
	@echo "Cleaning up [.pyc, .cap, .cache] files..."
	@sudo find . -type f -name "*.pyc" -delete
	@sudo find . -type f -name "*.cap" -delete
	@sudo find ./.cache/* -type f,d -not -name 'placeholder' -delete
	@echo "Cleaning complete!"
endif
