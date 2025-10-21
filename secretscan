import os
import re
import argparse
import csv
from pathlib import Path
from urllib.parse import urlparse

class SensitiveInfoScanner:
    def __init__(self):
        # 支持的文件扩展名
        self.supported_extensions = {
            '.java', '.js', '.jsx', '.ts', '.tsx',  # Java和JavaScript/TypeScript
            '.php', '.py', '.rb', '.go', '.rs',     # 其他后端语言
            '.cpp', '.c', '.h', '.hpp',             # C/C++
            '.cs', '.vb',                           # .NET
            '.swift', '.m', '.mm',                  # iOS/macOS
            '.kt', '.kts',                          # Kotlin
            '.scala', '.clj',                       # Scala/Clojure
            '.sh', '.bash', '.zsh',                 # Shell脚本
            '.ps1', '.bat', '.cmd',                 # Windows脚本
            '.sql', '.pl', '.r',                    # 数据库和脚本
            '.html', '.htm', '.xml', '.json',       # 标记语言
            '.yml', '.yaml', '.toml', '.ini',       # 配置文件
            '.properties', '.cfg', '.conf',
            '.txt', '.md', '.rst',                  # 文本文件
            '.gradle', '.groovy',                   # 构建脚本
            '.dockerfile', '.docker',               # Docker文件
        }
        
        # 更全面的敏感信息正则表达式模式
        self.patterns = {
            '硬编码密码': [
                r'password\s*[=:]\s*["\']([^"\']{4,})["\']',
                r'pwd\s*[=:]\s*["\']([^"\']{4,})["\']',
                r'passwd\s*[=:]\s*["\']([^"\']{4,})["\']',
                r'\.password\s*\(\s*["\']([^"\']{4,})["\']',
                r'\.pwd\s*\(\s*["\']([^"\']{4,})["\']',
                r'new\s+PasswordAuthentication\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']{4,})["\']\s*\)',
                r'"password"\s*:\s*"([^"]{4,})"',
                r"'password'\s*:\s*'([^']{4,})'"
            ],
            'API密钥/AppID': [
                r'api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'apikey\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'\.apiKey\s*\(\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'appId\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'\.appId\s*\(\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'appid\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'\.appid\s*\(\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'sk-[a-zA-Z0-9]{20,}',  # OpenAI密钥格式
                r'AKIA[0-9A-Z]{16}',  # AWS密钥格式
                r'gh[pousr]_[A-Za-z0-9_]{36}',  # GitHub密钥格式
                r'"api_key"\s*:\s*"([^"]{16,})"',
                r"'api_key'\s*:\s*'([^']{16,})'"
            ],
            'Secret密钥': [
                r'secret[_-]?key\s*[=:]\s*["\']([^"\']{8,})["\']',
                r'\.secretKey\s*\(\s*["\']([^"\']{8,})["\']',
                r'secret\s*[=:]\s*["\']([^"\']{8,})["\']',
                r'\.secret\s*\(\s*["\']([^"\']{8,})["\']',
                r'client[_-]?secret\s*[=:]\s*["\']([^"\']{8,})["\']',
                r'\.clientSecret\s*\(\s*["\']([^"\']{8,})["\']',
                r'"secret"\s*:\s*"([^"]{8,})"',
                r"'secret'\s*:\s*'([^']{8,})'"
            ],
            '访问令牌': [
                r'access[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'token\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'\.accessToken\s*\(\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'\.token\s*\(\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'bearer\s+[a-zA-Z0-9_-]{20,}',  # Bearer token
                r'"token"\s*:\s*"([^"]{16,})"',
                r"'token'\s*:\s*'([^']{16,})'",
                r'"access_token"\s*:\s*"([^"]{16,})"',
                r"'access_token'\s*:\s*'([^']{16,})'"
            ],
            '数据库连接字符串': [
                r'jdbc:(?:mysql|postgresql|oracle):(?:[^\s"\']*://)?[^\s"\']*:[0-9]+/[^\s"\']*',
                r'mongodb(?:\\+srv)?://[^\s"\']+',
                r'redis://[^\s"\']+',
                r'DataSource[^;]*=[^;]*;',
                r'mysql://[^\s"\']+',
                r'postgresql://[^\s"\']+',
                r'postgres://[^\s"\']+',
                r'"connectionString"\s*:\s*"[^"]*(?:jdbc|mongodb|redis|mysql|postgres)[^"]*"',
                r"'connectionString'\s*:\s*'[^']*(?:jdbc|mongodb|redis|mysql|postgres)[^']*'"
            ],
            '加密密钥': [
                r'encryption[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'aes[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'\.encryptionKey\s*\(\s*["\']([a-zA-Z0-9]{16,})["\']',
                r'"encryption_key"\s*:\s*"([^"]{16,})"',
                r"'encryption_key'\s*:\s*'([^']{16,})'"
            ],
            '邮箱配置': [
                r'mail\.(?:smtp\.)?password\s*[=:]\s*["\']([^"\']{4,})["\']',
                r'email\.password\s*[=:]\s*["\']([^"\']{4,})["\']',
                r'\.mailPassword\s*\(\s*["\']([^"\']{4,})["\']',
                r'smtp_password\s*[=:]\s*["\']([^"\']{4,})["\']',
                r'"smtp_password"\s*:\s*"([^"]{4,})"',
                r"'smtp_password'\s*:\s*'([^']{4,})'"
            ],
            'IP地址': [
                r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                r'ip\s*[=:]\s*["\']((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))["\']',
                r'host\s*[=:]\s*["\']((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))["\']',
            ],
            '域名': [
                r'\b(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::[0-9]{1,5})?\b',
                r'domain\s*[=:]\s*["\']([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}["\']',
                r'hostname\s*[=:]\s*["\']([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}["\']',
                r'baseUrl\s*[=:]\s*["\'](?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}["\']',
            ],
            'URL链接': [
                r'https?://[^\s"\']+',
                r'ftp://[^\s"\']+',
                r'ws://[^\s"\']+',
                r'wss://[^\s"\']+',
                r'url\s*[=:]\s*["\'](https?://[^"\']+)["\']',
                r'endpoint\s*[=:]\s*["\'](https?://[^"\']+)["\']',
                r'baseUrl\s*[=:]\s*["\'](https?://[^"\']+)["\']',
                r'server\s*[=:]\s*["\'](https?://[^"\']+)["\']',
            ],
            '配置文件敏感信息': [
                r'DATABASE_URL\s*[=:]\s*["\']([^"\']+)["\']',
                r'REDIS_URL\s*[=:]\s*["\']([^"\']+)["\']',
                r'AWS_ACCESS_KEY_ID\s*[=:]\s*["\']([^"\']+)["\']',
                r'AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']([^"\']+)["\']',
                r'STRIPE_SECRET_KEY\s*[=:]\s*["\']([^"\']+)["\']',
                r'STRIPE_PUBLISHABLE_KEY\s*[=:]\s*["\']([^"\']+)["\']',
                r'FACEBOOK_APP_SECRET\s*[=:]\s*["\']([^"\']+)["\']',
                r'GOOGLE_CLIENT_SECRET\s*[=:]\s*["\']([^"\']+)["\']',
                r'GITHUB_TOKEN\s*[=:]\s*["\']([^"\']+)["\']',
                r'SLACK_WEBHOOK\s*[=:]\s*["\']([^"\']+)["\']',
            ],
            '通用密钥模式': [
                # 匹配方法调用中的长字符串参数
                r'\.(?:key|secret|token|password|pwd|appId|appKey|apiKey|secretKey)\s*\(\s*["\']([^"\']{8,})["\']',
                # 匹配赋值中的长字符串值
                r'(?:key|secret|token|password|pwd|appId|appKey|apiKey|secretKey)\s*[=:]\s*["\']([^"\']{8,})["\']',
                # JSON格式的密钥
                r'"(?:apiKey|secretKey|accessToken|password)"\s*:\s*"([^"]{8,})"',
                r"'(?:apiKey|secretKey|accessToken|password)'\s*:\s*'([^']{8,})'",
            ]
        }
    
    def is_valid_sensitive_info(self, category, text):
        """验证是否为真正的敏感信息"""
        # 排除常见的测试值
        test_values = [
            'test', 'example', 'demo', 'sample', 'dummy', 'null', 'none',
            'password', '1234', '123456', '12345678', 'admin', 'root',
            'localhost', '127.0.0.1', '0.0.0.0', 'example.com',
            'your_', 'my_', 'placeholder', 'changeme', 'secret',
            'api_key', 'token', 'key'
        ]
        
        text_lower = text.lower()
        
        # 检查是否是测试值
        if any(test in text_lower for test in test_values):
            return False
        
        # 根据类别进行特定验证
        if category == 'IP地址':
            return self.is_valid_ip(text)
        elif category == '域名':
            return self.is_valid_domain(text)
        elif category == 'URL链接':
            return self.is_valid_url(text)
        elif category in ['硬编码密码', 'API密钥/AppID', 'Secret密钥', '访问令牌', '加密密钥']:
            # 对于密钥类信息，检查长度和复杂度
            if len(text) < 8:
                return False
            
            # 检查是否是过于简单的值
            if re.match(r'^[0-9]+$', text) and len(text) < 16:  # 纯数字且较短
                return False
            
            if re.match(r'^[a-z]+$', text_lower) and len(text) < 10:  # 纯小写字母且较短
                return False
        
        return True
    
    def is_valid_ip(self, ip):
        """验证IP地址是否有效"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        # 排除私有IP和特殊IP
        if (ip.startswith('10.') or 
            ip.startswith('192.168.') or 
            (ip.startswith('172.') and 16 <= int(parts[1]) <= 31) or 
            ip in ['127.0.0.1', '0.0.0.0', '255.255.255.255']):
            return False
        return True
    
    def is_valid_domain(self, domain):
        """验证域名是否有效"""
        # 移除协议部分
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # 移除路径和端口
        domain = domain.split('/')[0].split(':')[0]
        
        # 简单的域名验证
        if len(domain) < 3 or len(domain) > 253:
            return False
        if domain.startswith('.') or domain.endswith('.'):
            return False
        if '..' in domain:
            return False
        
        # 排除常见测试域名
        test_domains = ['example.com', 'test.com', 'localhost', 'example.org', 
                       'test.org', 'demo.com', 'sample.com', 'localhost.localdomain']
        if any(test in domain.lower() for test in test_domains):
            return False
        
        # 验证域名格式
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))
    
    def is_valid_url(self, url):
        """验证URL是否有效"""
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
            
            # 排除测试URL
            test_urls = ['example.com', 'test.com', 'localhost', '127.0.0.1']
            if any(test in result.netloc.lower() for test in test_urls):
                return False
            
            # 验证常见协议
            valid_schemes = ['http', 'https', 'ftp', 'ws', 'wss']
            if result.scheme.lower() not in valid_schemes:
                return False
            
            return True
        except:
            return False
    
    def scan_file(self, file_path):
        """扫描单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                lines = content.split('\n')
                
                findings = []
                
                for line_num, line in enumerate(lines, 1):
                    # 跳过明显的注释行（针对不同语言）
                    line_stripped = line.strip()
                    comment_patterns = [
                        line_stripped.startswith('//'),
                        line_stripped.startswith('#'),
                        line_stripped.startswith('--'),
                        line_stripped.startswith('/*'),
                        line_stripped.startswith('*'),
                        line_stripped.startswith('"""'),
                        line_stripped.startswith("'''"),
                    ]
                    if any(comment_patterns):
                        continue
                    
                    for category, regex_list in self.patterns.items():
                        for pattern in regex_list:
                            matches = re.finditer(pattern, line, re.IGNORECASE)
                            for match in matches:
                                # 提取匹配的内容
                                if len(match.groups()) > 0:
                                    for group_num, matched_text in enumerate(match.groups(), 1):
                                        if matched_text and self.is_valid_sensitive_info(category, matched_text):
                                            findings.append({
                                                'file': str(file_path),
                                                'line': line_num,
                                                'category': category,
                                                'matched_text': matched_text,
                                                'full_line': line.strip()[:200],
                                                'file_type': file_path.suffix.lower()
                                            })
                                else:
                                    matched_text = match.group()
                                    if self.is_valid_sensitive_info(category, matched_text):
                                        findings.append({
                                            'file': str(file_path),
                                            'line': line_num,
                                            'category': category,
                                            'matched_text': matched_text,
                                            'full_line': line.strip()[:200],
                                            'file_type': file_path.suffix.lower()
                                        })
                
                return findings
                
        except Exception as e:
            print(f"读取文件 {file_path} 时出错: {e}")
            return []
    
    def scan_directory(self, directory_path):
        """递归扫描目录中的所有支持文件"""
        all_files = []
        directory_path = Path(directory_path)
        
        if not directory_path.exists():
            print(f"目录不存在: {directory_path}")
            return []
        
        # 递归查找所有支持的文件
        for file_path in directory_path.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in self.supported_extensions:
                all_files.append(file_path)
        
        # 按文件类型统计
        file_types = {}
        for file_path in all_files:
            ext = file_path.suffix.lower()
            file_types[ext] = file_types.get(ext, 0) + 1
        
        print(f"找到 {len(all_files)} 个支持的文件：")
        for ext, count in sorted(file_types.items()):
            print(f"  {ext}: {count} 个")
        
        all_findings = []
        for file_path in all_files:
            findings = self.scan_file(file_path)
            all_findings.extend(findings)
        
        return all_findings
    
    def generate_csv_report(self, findings, csv_file):
        """生成CSV格式扫描报告"""
        if not findings:
            print("未发现敏感信息，不生成CSV文件")
            return
        
        # CSV文件头
        fieldnames = ['文件路径', '文件类型', '行号', '信息类型', '匹配内容', '完整代码行']
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for finding in findings:
                    writer.writerow({
                        '文件路径': finding['file'],
                        '文件类型': finding.get('file_type', 'unknown'),
                        '行号': finding['line'],
                        '信息类型': finding['category'],
                        '匹配内容': finding['matched_text'],
                        '完整代码行': finding['full_line']
                    })
            
            print(f"CSV报告已保存到: {csv_file}")
            print(f"总共发现 {len(findings)} 条敏感信息")
            
        except Exception as e:
            print(f"生成CSV文件时出错: {e}")
    
    def print_summary(self, findings):
        """打印扫描摘要"""
        if not findings:
            print("🎉 未发现敏感信息")
            return
        
        # 按类别统计
        category_count = {}
        file_type_count = {}
        
        for finding in findings:
            category = finding['category']
            file_type = finding.get('file_type', 'unknown')
            
            category_count[category] = category_count.get(category, 0) + 1
            file_type_count[file_type] = file_type_count.get(file_type, 0) + 1
        
        print(f"\n🔍 扫描完成！共发现 {len(findings)} 条敏感信息：")
        print(f"\n📊 按信息类型统计：")
        for category, count in sorted(category_count.items()):
            print(f"   {category}: {count} 条")
        
        print(f"\n📁 按文件类型统计：")
        for file_type, count in sorted(file_type_count.items()):
            print(f"   {file_type}: {count} 条")
        
        # 显示前几个发现作为示例
        print(f"\n📋 示例发现：")
        for i, finding in enumerate(findings[:5]):
            print(f"   {i+1}. [{finding['category']}] {finding['matched_text']}")

def main():
    parser = argparse.ArgumentParser(description='多语言文件敏感信息扫描工具')
    parser.add_argument('directory', help='要扫描的目录路径')
    parser.add_argument('-o', '--output', default='sensitive_info_report.csv', 
                       help='CSV报告输出文件路径 (默认: sensitive_info_report.csv)')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出模式')
    parser.add_argument('--extensions', help='指定额外的文件扩展名，用逗号分隔（例如：.vue,.sass,.less）')
    
    args = parser.parse_args()
    
    scanner = SensitiveInfoScanner()
    
    # 添加用户指定的扩展名
    if args.extensions:
        extra_extensions = set(ext.strip().lower() for ext in args.extensions.split(','))
        scanner.supported_extensions.update(extra_extensions)
        print(f"添加了额外的文件扩展名: {', '.join(extra_extensions)}")
    
    if args.verbose:
        print(f"开始扫描目录: {args.directory}")
        print(f"支持的文件类型: {len(scanner.supported_extensions)} 种")
    
    findings = scanner.scan_directory(args.directory)
    
    scanner.print_summary(findings)
    scanner.generate_csv_report(findings, args.output)

if __name__ == "__main__":
    # 如果直接运行，使用示例
    if len(os.sys.argv) == 1:
        directory = input("请输入要扫描的目录路径（默认为当前目录）: ").strip()
        if not directory:
            directory = "."
        
        output_file = input("请输入CSV报告文件路径（默认: sensitive_info_report.csv）: ").strip()
        if not output_file:
            output_file = "sensitive_info_report.csv"
        
        extra_extensions = input("请输入额外的文件扩展名，用逗号分隔（可选）: ").strip()
        
        scanner = SensitiveInfoScanner()
        
        if extra_extensions:
            extra_extensions_set = set(ext.strip().lower() for ext in extra_extensions.split(','))
            scanner.supported_extensions.update(extra_extensions_set)
            print(f"添加了额外的文件扩展名: {', '.join(extra_extensions_set)}")
        
        findings = scanner.scan_directory(directory)
        scanner.print_summary(findings)
        scanner.generate_csv_report(findings, output_file)
    else:
        main()
