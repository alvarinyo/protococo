from setuptools import setup

from protococo import __version__

setup(
    name='protococo',
    version=__version__,
    url='https://github.com/alvarinyo/protococo',
    license='MIT',
    description='protococo helps you design, test and debug custom binary protocols',
    author='Alvaro Luis Pierna',
    author_email='alvaro.luispierna@gmail.com',

    py_modules=['protococo'],
    install_requires=['docopt'],
    entry_points="""
    [console_scripts]
    protococo = protococo:cli_main
    """,
    
    classifiers=[
		'Development Status :: 4 - Beta',
		'Environment :: Console',
		'Intended Audience :: Developers',
		'License :: OSI Approved :: MIT License',
		'Operating System :: OS Independent',
		'Programming Language :: Python',
		'Topic :: Software Development',
		'Topic :: Utilities',
	],
)
