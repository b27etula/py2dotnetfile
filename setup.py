from setuptools import setup, find_packages

setup(
    name='py2dotnetfile',
    version='0.1.0',
    author='Bob Jung, Yaron Samuel, Dominik Reichel',
    description='Library to parse the CLR header of .NET assemblies',
    packages=find_packages(),
    package_dir={'py2dotnetfile': 'py2dotnetfile'},
    install_requires=[
        'pefile'
    ],
    python_requires='==2.7.12'
)
