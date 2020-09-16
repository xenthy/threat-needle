ifeq ($(OS),Windows_NT)
	CC=py
else
	CC=python3
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
	@echo Cleaned up .pyc and .cap files
else
	@$(RM) -r *.pyc
	@$(RM) -r *.cap
	@echo Cleaned up .pyc and .cap files
endif