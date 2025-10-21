# secretscan
搜索指定文件夹中所有能搜到的敏感信息,我一般用来搜索小程序和app代码
正则和改进建议都可以提
# 基本用法
python scanner.py /path/to/project

# 指定输出文件
python scanner.py /path/to/project -o my_report.csv

# 详细模式
python scanner.py /path/to/project -v

# 添加自定义文件扩展名
python scanner.py /path/to/project --extensions ".vue,.sass,.less"

# 组合使用
python scanner.py /path/to/project -o report.csv -v --extensions ".vue,.scss"
<img width="1485" height="624" alt="image" src="https://github.com/user-attachments/assets/0a359197-1e1b-4610-bf1a-a9e52f1ce976" />
