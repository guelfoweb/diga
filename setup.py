from setuptools import setup

setup(
    name='diga',
    version='0.1.0',
    description='Domain Inspector Global Audit',
    url='https://github.com/guelfoweb/diga',
    author='Gianni Amato',
    author_email='guelfoweb@gmail.com',
    license='GPL-3.0',
    packages=['diga'],
    install_requires=['requests==2.31.0', 'dnspython==2.4.2', 'pyOpenSSL==23.3.0'],
    entry_points={
        'console_scripts': [
            'diga=diga.diga:main',
        ],
    }
)
