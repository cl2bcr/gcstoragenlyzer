from setuptools import setup, find_packages

setup(
    name='gcstoragenlyzer',

    version='0.1.0',

    packages=find_packages(),

    install_requires=[
        'google-cloud-storage',
        'click',
        'python-dotenv',
    ],

    entry_points={
        'console_scripts': [
            'gcstoragenlyzer = gcstoragenlyzer.cli:main',
        ],
    },

    author='Celebi Bicer',
    description='GCS Storage Analyzer for accessible buckets and exposed detection.',
    license='MIT',
    keywords='gcs google cloud storage security analyzer',
)
