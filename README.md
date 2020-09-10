# ict2202-assignment-1 <!-- omit in toc -->

## Table of Contents <!-- omit in toc -->
- [Setting Up](#setting-up)
	- [Cloning GitHub Repository (using vscode)](#cloning-github-repository-using-vscode)
- [Installing Dependencies](#installing-dependencies)
- [Using Make](#using-make)
	- [Windows](#windows)
	- [Linux](#linux)
	- [Running the Project](#running-the-project)
- [Project Details](#project-details)
- [Milestones](#milestones)
- [Collaborators](#collaborators)

## Setting Up
### Cloning GitHub Repository (using [vscode](https://code.visualstudio.com/))
1. Press: Ctrl + Shift + P
2. Type: 'Clone' and select 'Git: Clone'
3. Paste `https://github.com/xenthy/ict2202-assignment-1`
4. Enter your GitHub credentials & select a location to save the repository

## Installing Dependencies
1. Install [Npcap](https://nmap.org/npcap/#download)
2. Install requirements:
```bash
> cd \Path\to\ict2202-assignment-1
> pip install -r requirements.txt
```

## Using Make
### Windows
1. [Install](https://sourceforge.net/projects/gnuwin32/files/make/3.81/make-3.81.exe/download?use_mirror=nchc&download=) Make for Windows
2. Set up environment PATH, if not you will not be unable to run `make`
   1. Right-click on 'This PC' > Properties > Advance System Settings > Environment Variables
   2. Under System Variable, Select PATH
   3. Click on Edit, enter Make location. Usually: `C:\Program Files (x86)\GnuWin32\bin`
### Linux
1. In terminal:
```bash
> sudo apt-get install build-essential -y
```
### Running the Project
1. To run the program
```bash
> cd \Path\to\ict2202-assignment-1
> make
```
2. To clean compiled files (.pyc)
```bash
> make clean
```

> If you are using vscode, you will need to restart your PC

## Project Details
???

## Milestones
- [ ] Project Outline
- [ ] TBD
- [ ] TBD

## Collaborators
| Name                | GitHub                                     | Job Scope          |
| ------------------- | ------------------------------------------ | ------------------ |
| **Zen Tan**         | [@xenthy](https://github.com/xenthy)       | Scaffold & Dumping |
| **Wong Chong Peng** | [@chong00](https://github.com/chong00)     | Base Features      |
| **Tan Yee Tat**     | [@ethancunt](https://github.com/ethancunt) | IOC                |
