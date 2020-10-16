# ict2202-assignment-1 <!-- omit in toc -->

## Table of Contents <!-- omit in toc -->
- [Setting Up](#setting-up)
  - [Windows](#windows)
    - [Cloning GitHub Repository (using vscode)](#cloning-github-repository-using-vscode)
    - [Installing Python](#installing-python)
    - [Installing Dependencies](#installing-dependencies)
    - [Setting up GNU Make](#setting-up-gnu-make)
  - [Linux (Debian)](#linux-debian)
    - [Cloning GitHub Repository](#cloning-github-repository)
    - [Configuring](#configuring)
- [Running the Project](#running-the-project)
- [Project Details](#project-details)
- [Milestones](#milestones)
- [Collaborators](#collaborators)

## Setting Up
### Windows
#### Cloning GitHub Repository (using [vscode](https://code.visualstudio.com/))
1. Press: Ctrl + Shift + P
2. Type: 'Clone' and select 'Git: Clone'
3. Paste `https://github.com/xenthy/ict2202-assignment-1`
4. Enter your GitHub credentials & select a location to save the repository

#### Installing Python
1. [Install](https://www.python.org/ftp/python/3.8.5/python-3.8.5-amd64.exe) python
2. Set up environment PATH, if not you will not be unable to run `py`/`python` 
    1. Right-click on 'This PC' > Properties > Advance System Settings > Environment Variables
    2. Under System Variable, Select PATH
    3. Click on Edit, enter location. Usually: `C:\Python38\`

> If you are using vscode, relaunch it

#### Installing Dependencies
1. Install pip requirements
```bash
> cd \Path\to\ict2202-assignment-1
> pip install -r requirements.txt
```
2. Install additional dependencies
- Install [codecs](https://files3.codecguide.com/K-Lite_Codec_Pack_1575_Basic.exe)

#### Setting up GNU Make
1. [Install](https://sourceforge.net/projects/gnuwin32/files/make/3.81/make-3.81.exe/download?use_mirror=nchc&download=) Make for Windows
2. Set up environment PATH, if not you will not be unable to run `make`
   1. Right-click on 'This PC' > Properties > Advance System Settings > Environment Variables
   2. Under System Variable, Select PATH
   3. Click on Edit, enter Make location. Usually: `C:\Program Files (x86)\GnuWin32\bin`

### Linux (Debian)
#### Cloning GitHub Repository
```bash
> sudo apt install git -y
> git clone https://github.com/xenthy/ict2202-assignment-1
```

#### Configuring
```bash
> cd \Path\to\ict2202-assignment-1
> ./configure
```

## Running the Project
1. To run the program
```bash
> cd \Path\to\ict2202-assignment-1
> make (password required)
```
2. To clean temp files (.pyc, .cap, ./.cache)
```bash
> make clean
```

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
