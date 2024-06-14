from setuptools import setup, find_packages

setup(
    name='wee-bot',  # 项目名称
    version='0.1.0',  # 项目版本
    description='A short description of the project',  # 项目描述
    long_description=open('README.md').read(),  # 项目详细描述，通常从 README 文件中读取
    long_description_content_type='text/markdown',  # README 文件的格式
    author='atorber',  # 作者名称
    author_email='atorber@163.com',  # 作者邮箱
    url='https://github.com/atorber/WeeBot',  # 项目主页 URL
    license='MIT',  # 项目许可证
    packages=find_packages(where='src'),  # 自动发现并包含项目中的所有包
    package_dir={'': 'src'},  # 指定包的根目录
    include_package_data=True,  # 包含包内的所有非代码文件
    install_requires=[  # 项目依赖项
        'frida>=16.2.1'
    ],
    extras_require={  # 可选依赖项
        'dev': [],
    },
    entry_points={  # 定义项目的可执行脚本
        'console_scripts': [],
    },
    classifiers=[  # 项目的分类标签
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',  # Python 版本要求
)