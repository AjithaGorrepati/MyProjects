from setuptools import setup

APP = ['client_gui.py']
DATA_FILES = ['client_private_key.pem', 'client_public_key.pem', 'public_key.pem']
OPTIONS = {
    'argv_emulation': True,
    'includes': ['tkinter', 'tkinterdnd2', 'cryptography', 'pandas', 'fpdf'],
    'packages': ['tkinterdnd2'],
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
