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
	powershell "(Get-ChildItem * -Include *.pyc -Recurse | Remove-Item)"
else
	$(RM) -r *.pyc
endif