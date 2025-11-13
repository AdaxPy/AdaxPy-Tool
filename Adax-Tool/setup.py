from setuptools import setup, find_packages

setup(
    name="AdaxTool",
    version="1.0.0",
    author="Adax",  
    description="Ein Python-Multitool für verschiedene Aufgaben (Adax MultiTool).",
    packages=find_packages(),
    py_modules=["Adax_MultiTool"],
    install_requires=[
        
    ],
    entry_points={
        "console_scripts": [
            "adax-tool=Adax_MultiTool:main",  
          
        ],
    },
    python_requires=">=3.8",
)
