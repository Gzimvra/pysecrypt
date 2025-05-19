import pathlib

import setuptools

setuptools.setup(
    name="PySecrypt",
    version="0.1.0",
    description="A command-line tool for educational demonstrations of encryption techniques",
    long_description=pathlib.Path("README.md").read_text(),
    long_description_content_type="text/markdown",
    author="George Zimvragos",
    author_email="gzymvragos22b@amcstudent.edu.gr",
    license="Free to use",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Intended Audience :: Education",
        "Development Status :: 4 - Beta",
    ],
    python_requires=">=3.13",
    install_requires=["cryptography >= 44.0.0", "tqdm >= 4.67.1"],
    packages=setuptools.find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "PySecrypt = PySecrypt.cli:main",
        ]
    },
)
