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
	$(CC) -m py_compile $(SOURCES)

clean:
ifeq ($(OS),Windows_NT)
	@powershell "(Get-ChildItem * -Include *.pyc -Recurse | Remove-Item)"
	@powershell "(Get-ChildItem * -Include *.cap -Recurse | Remove-Item)"
	@echo Cleaned up .pyc, .cap files and .cache files
else
	@echo "Cleaning up workspace..."
	@$(RM) -r *.pyc
	@$(RM) -r *.cap
	@sudo find ./.cache/* -type f,d -not -name 'placeholder' -delete
	@echo Cleaned up .pyc, .cap files and .cache files
endif
