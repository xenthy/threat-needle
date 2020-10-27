<p align="center">
➡️
    <a href="https://github.com/xenthy/ict2202-assignment-1#-installation-guide">Installation Guide</a> |
    <a href="https://github.com/xenthy/ict2202-assignment-1#-usage">Usage Guide</a>
⬅️
    <br>
    <img src="pictures/rustscan.png" height=400px width=400px>
</p>
<p align="center">
<u><b> Making network forensics easy </b></u><br> Run the program, <b>sit back</b>, and relax.
</p>

<hr>

| <p align="center"><a href="https://hub.docker.com/r/cmnatic/rustscan"> 👩‍💻 Linux (Debian) Recommended </a></p>    | <p align="center"><a href="https://github.com/RustScan/RustScan/releases">🪟 Windows </p> | <p align="center"><a href="https://aur.archlinux.org/packages/rustscan/"> 🐋 Docker </a></p>                      |
| --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| <p align="center"><img src="https://github.com/RustScan/RustScan/blob/master/pictures/kali.png?raw=true" /></p> | <p align="center"><img src=/></p>                                                        | <p align="center"><img src="https://github.com/RustScan/RustScan/blob/master/pictures/docker.png?raw=true"/></p> | <p align="center"><img src="https://github.com/RustScan/RustScan/blob/master/pictures/rust.png?raw=true" /></p> |
| [Install Guide](https://github.com/xenthy/ict2202-assignment-1#️-linux-debian)                                   | [Install guide](https://github.com/xenthy/ict2202-assignment-1#️-windows)                 |                                                                                                                  |

<hr>

- [🛠️ Installation Guide](#️-installation-guide)
  - [🖥️ Linux (Debian)](#️-linux-debian)
  - [🪟 Windows](#-windows)
- [Running the Application](#running-the-application)
- [Usage](#usage)
  - [Collaborators](#collaborators)

# 🛠️ Installation Guide
## 🖥️ Linux (Debian)
**Cloning GitHub Repository:**
```bash
> sudo apt install git -y
> git clone https://github.com/xenthy/ict2202-assignment-1
```

**Auto Configuring:**
```bash
> cd \Path\to\ict2202-assignment-1
> ./configure
```

## 🪟 Windows
**Cloning GitHub Repository:**
```bash
> git clone https://github.com/xenthy/ict2202-assignment-1
```

**Installing Python 3.8.5:**
1. [Install](https://www.python.org/ftp/python/3.8.5/python-3.8.5-amd64.exe) python
2. Set up environment PATH, if not you will not be unable to run `py`/`python` 
    1. Right-click on 'This PC' > Properties > Advance System Settings > Environment Variables
    2. Under System Variable, Select PATH
    3. Click on Edit, enter location. Usually: `C:\Python38\`

**Installing Dependencies:**
```bash
> cd \Path\to\ict2202-assignment-1
> pip install -r requirements.txt
```

**Setting up GNU Make:**
1. [Install](https://sourceforge.net/projects/gnuwin32/files/make/3.81/make-3.81.exe/download?use_mirror=nchc&download=) Make for Windows
2. Set up environment PATH, if not you will not be unable to run `make`
   1. Right-click on 'This PC' > Properties > Advance System Settings > Environment Variables
   2. Under System Variable, Select PATH
   3. Click on Edit, enter Make location. Usually: `C:\Program Files (x86)\GnuWin32\bin`


# Running the Application
1. To run the program
```bash
> cd \Path\to\ict2202-assignment-1
> make (password required)
```
2. To clean temporary files (.pyc, .cap, ./.cache)
```bash
> make clean
```

# Usage

## Collaborators
| Name                | GitHub                                     |
| ------------------- | ------------------------------------------ |
| **Zen Tan**         | [@xenthy](https://github.com/xenthy)       |
| **Wong Chong Peng** | [@chong00](https://github.com/chong00)     |
| **Tan Yee Tat**     | [@ethancunt](https://github.com/ethancunt) |
