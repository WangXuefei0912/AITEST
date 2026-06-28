import os
import re
import hashlib
import csv
import requests
from typing import List, Dict, Tuple, Optional

# 漏洞规则定义
VULNERABILITY_RULES = {
    "PHP文件包含": {
        "cwe": "CWE-98",
        "patterns": [
            r"include\s*\(\s*['\"]?\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)\b",
            r"require\s*\(\s*['\"]?\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)\b",
            r"include_once\s*\(\s*['\"]?\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)\b",
            r"require_once\s*\(\s*['\"]?\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)\b",
            r"include\s*\(\s*['\"]?\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*['\"]?\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)\b"
        ],
        "description": "PHP文件包含漏洞，允许攻击者包含恶意文件"
    },
    "SQL注入": {
        "cwe": "CWE-89",
        "patterns": [
            r"mysql_query\s*\(\s*['\"]?SELECT|INSERT|UPDATE|DELETE|UNION|DROP|ALTER\b.*\$\w+",
            r"mysqli_query\s*\(\s*['\"]?SELECT|INSERT|UPDATE|DELETE|UNION|DROP|ALTER\b.*\$\w+",
            r"PDO::query\s*\(\s*['\"]?SELECT|INSERT|UPDATE|DELETE|UNION|DROP|ALTER\b.*\$\w+",
            r"exec\s*\(\s*['\"]?SELECT|INSERT|UPDATE|DELETE|UNION|DROP|ALTER\b.*\$\w+",
            r"shell_exec\s*\(\s*['\"]?SELECT|INSERT|UPDATE|DELETE|UNION|DROP|ALTER\b.*\$\w+"
        ],
        "description": "SQL注入漏洞，允许攻击者操纵数据库查询"
    },
    "OS命令注入": {
        "cwe": "CWE-78",
        "patterns": [
            r"system\s*\(\s*['\"]?\$\w+",
            r"exec\s*\(\s*['\"]?\$\w+",
            r"shell_exec\s*\(\s*['\"]?\$\w+",
            r"passthru\s*\(\s*['\"]?\$\w+",
            r"popen\s*\(\s*['\"]?\$\w+",
            r"proc_open\s*\(\s*['\"]?\$\w+"
        ],
        "description": "OS命令注入漏洞，允许攻击者执行系统命令"
    },
    "跨站脚本（XSS）": {
        "cwe": "CWE-79",
        "patterns": [
            r"echo\s*\$\w+",
            r"print\s*\$\w+",
            r"printf\s*\$\w+",
            r"print_r\s*\$\w+",
            r"var_dump\s*\$\w+",
            r"htmlentities\s*\(\s*\$\w+\s*\)\s*;",
            r"htmlspecialchars\s*\(\s*\$\w+\s*\)\s*;",
            r"echo\s*['\"]?<\s*script\b",
            r"echo\s*['\"]?<\s*iframe\b",
            r"echo\s*['\"]?<\s*img\s+src\s*=\s*['\"]?javascript:",
            r"echo\s*['\"]?<\s*svg\s+onload\s*=\s*['\"]?javascript:",
            r"echo\s*\$\w+\s*\.?\s*html"
        ],
        "description": "跨站脚本漏洞，允许攻击者注入恶意脚本"
    },
    "反序列化不可信数据": {
        "cwe": "CWE-502",
        "patterns": [
            r"unserialize\s*\(\s*['\"]?\$\w+",
            r"unserialize\s*\(\s*['\"]?base64_decode\s*\(\s*['\"]?\$\w+"
        ],
        "description": "反序列化漏洞，允许攻击者执行恶意代码"
    },
    "硬编码凭据": {
        "cwe": "CWE-798",
        "patterns": [
            r"define\s*\(\s*['\"]?DB_USER['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"define\s*\(\s*['\"]?DB_PASSWORD['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"define\s*\(\s*['\"]?DB_HOST['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"define\s*\(\s*['\"]?DB_NAME['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$db_user\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$db_password\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$db_host\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$db_name\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?"
        ],
        "description": "硬编码凭据，可能导致凭据泄露"
    },
    "敏感信息存储不安全": {
        "cwe": "CWE-312",
        "patterns": [
            r"md5\s*\(\s*['\"]?[a-zA-Z0-9_]+['\"]?\s*\)",
            r"sha1\s*\(\s*['\"]?[a-zA-Z0-9_]+['\"]?\s*\)",
            r"password_hash\s*\(\s*['\"]?[a-zA-Z0-9_]+['\"]?\s*,\s*PASSWORD_DEFAULT\s*\)",
            r"password_verify\s*\(\s*['\"]?[a-zA-Z0-9_]+['\"]?\s*,\s*\$\w+"
        ],
        "description": "敏感信息存储不安全，可能使用弱哈希算法"
    },
    "缺少授权": {
        "cwe": "CWE-862",
        "patterns": [
            r"if\s*\(\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?admin['\"]?\s*\)\s*\{"
        ],
        "description": "缺少授权检查，可能导致未授权访问"
    },
    "路径遍历": {
        "cwe": "CWE-22",
        "patterns": [
            r"include\s*\(\s*['\"]?\.\.?\/",
            r"require\s*\(\s*['\"]?\.\.?\/",
            r"include_once\s*\(\s*['\"]?\.\.?\/",
            r"require_once\s*\(\s*['\"]?\.\.?\/",
            r"file_get_contents\s*\(\s*['\"]?\.\.?\/",
            r"file_put_contents\s*\(\s*['\"]?\.\.?\/",
            r"fopen\s*\(\s*['\"]?\.\.?\/",
            r"readfile\s*\(\s*['\"]?\.\.?\/"
        ],
        "description": "路径遍历漏洞，允许攻击者访问任意文件"
    },
    "开放重定向": {
        "cwe": "CWE-601",
        "patterns": [
            r"header\s*\(\s*['\"]?Location\s*:\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Location\s*:\s*['\"]?\.\.?\/",
            r"header\s*\(\s*['\"]?Location\s*:\s*['\"]?http:\/\/",
            r"header\s*\(\s*['\"]?Location\s*:\s*['\"]?https:\/\/"
        ],
        "description": "开放重定向漏洞，可能导致钓鱼攻击"
    },
    "文件名或路径的外部控制": {
        "cwe": "CWE-73",
        "patterns": [
            r"file_get_contents\s*\(\s*['\"]?\$\w+",
            r"file_put_contents\s*\(\s*['\"]?\$\w+",
            r"unlink\s*\(\s*['\"]?\$\w+",
            r"rename\s*\(\s*['\"]?\$\w+",
            r"copy\s*\(\s*['\"]?\$\w+",
            r"move_uploaded_file\s*\(\s*['\"]?\$\w+"
        ],
        "description": "文件名或路径的外部控制，可能导致文件操作漏洞"
    },
    "错误信息中的信息泄露": {
        "cwe": "CWE-209",
        "patterns": [
            r"error_reporting\s*\(\s*E_ALL\s*\)",
            r"ini_set\s*\(\s*['\"]?display_errors['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?display_startup_errors['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?log_errors['\"]?\s*,\s*['\"]?Off['\"]?",
            r"ini_set\s*\(\s*['\"]?error_log['\"]?\s*,\s*['\"]?Off['\"]?"
        ],
        "description": "错误信息中的信息泄露，可能暴露敏感信息"
    },
    "Cookie未设置Secure属性": {
        "cwe": "CWE-614",
        "patterns": [
            r"setcookie\s*\(\s*['\"]?\w+['\"]?\s*,\s*['\"]?\$\w+",
            r"setcookie\s*\(\s*['\"]?\w+['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"setrawcookie\s*\(\s*['\"]?\w+['\"]?\s*,\s*['\"]?\$\w+",
            r"setrawcookie\s*\(\s*['\"]?\w+['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?"
        ],
        "description": "Cookie未设置Secure属性，可能导致会话劫持"
    },
    "Cookie未设置HttpOnly属性": {
        "cwe": "CWE-1004",
        "patterns": [
            r"setcookie\s*\(\s*['\"]?\w+['\"]?\s*,\s*['\"]?\$\w+",
            r"setcookie\s*\(\s*['\"]?\w+['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"setrawcookie\s*\(\s*['\"]?\w+['\"]?\s*,\s*['\"]?\$\w+",
            r"setrawcookie\s*\(\s*['\"]?\w+['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?"
        ],
        "description": "Cookie未设置HttpOnly属性，可能导致XSS攻击"
    },
    "会话过期不足": {
        "cwe": "CWE-613",
        "patterns": [
            r"ini_set\s*\(\s*['\"]?session.gc_maxlifetime['\"]?\s*,\s*['\"]?\d+['\"]?",
            r"session_set_cookie_params\s*\(\s*\d+",
            r"ini_set\s*\(\s*['\"]?session.cookie_lifetime['\"]?\s*,\s*['\"]?\d+['\"]?"
        ],
        "description": "会话过期不足，可能导致会话劫持"
    },
    "XML外部实体注入（XXE）": {
        "cwe": "CWE-611",
        "patterns": [
            r"simplexml_load_file\s*\(\s*['\"]?\$\w+",
            r"simplexml_load_string\s*\(\s*['\"]?\$\w+",
            r"DOMDocument::load\s*\(\s*['\"]?\$\w+",
            r"DOMDocument::loadXML\s*\(\s*['\"]?\$\w+",
            r"XmlParser::parse\s*\(\s*['\"]?\$\w+"
        ],
        "description": "XML外部实体注入漏洞，可能导致信息泄露"
    },
    "LDAP注入": {
        "cwe": "CWE-90",
        "patterns": [
            r"ldap_search\s*\(\s*['\"]?\$\w+",
            r"ldap_add\s*\(\s*['\"]?\$\w+",
            r"ldap_modify\s*\(\s*['\"]?\$\w+",
            r"ldap_delete\s*\(\s*['\"]?\$\w+"
        ],
        "description": "LDAP注入漏洞，可能导致目录服务攻击"
    },
    "XPath注入": {
        "cwe": "CWE-643",
        "patterns": [
            r"xpath_query\s*\(\s*['\"]?\$\w+",
            r"DOMXPath::query\s*\(\s*['\"]?\$\w+",
            r"SimpleXMLElement::xpath\s*\(\s*['\"]?\$\w+"
        ],
        "description": "XPath注入漏洞，可能导致XML数据泄露"
    },
    "不安全的直接对象引用（IDOR）": {
        "cwe": "CWE-284",
        "patterns": [
            r"echo\s*\$\w+\s*->\s*\$\w+",
            r"print\s*\$\w+\s*->\s*\$\w+",
            r"var_dump\s*\$\w+\s*->\s*\$\w+",
            r"print_r\s*\$\w+\s*->\s*\$\w+",
            r"json_encode\s*\(\s*\$\w+\s*->\s*\$\w+"
        ],
        "description": "不安全的直接对象引用，可能导致未授权数据访问"
    },
    "动态代码执行（eval注入）": {
        "cwe": "CWE-95",
        "patterns": [
            r"eval\s*\(\s*['\"]?\$\w+",
            r"assert\s*\(\s*['\"]?\$\w+",
            r"create_function\s*\(\s*['\"]?\$\w+",
            r"preg_replace\s*\(\s*['\"]?e['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "动态代码执行漏洞，可能导致任意代码执行"
    },
    "上传危险类型文件": {
        "cwe": "CWE-434",
        "patterns": [
            r"move_uploaded_file\s*\(\s*['\"]?\$\w+",
            r"copy\s*\(\s*['\"]?\$\w+",
            r"file_put_contents\s*\(\s*['\"]?\$\w+",
            r"file_get_contents\s*\(\s*['\"]?\$\w+"
        ],
        "description": "上传危险类型文件，可能导致恶意文件上传"
    },
    "资源耗尽（拒绝服务）": {
        "cwe": "CWE-400",
        "patterns": [
            r"str_repeat\s*\(\s*['\"]?\$\w+",
            r"str_pad\s*\(\s*['\"]?\$\w+",
            r"array_fill\s*\(\s*['\"]?\$\w+",
            r"array_fill_keys\s*\(\s*['\"]?\$\w+",
            r"range\s*\(\s*['\"]?\$\w+",
            r"array_merge\s*\(\s*['\"]?\$\w+"
        ],
        "description": "资源耗尽漏洞，可能导致拒绝服务攻击"
    },
    "竞争条件": {
        "cwe": "CWE-362",
        "patterns": [
            r"file_put_contents\s*\(\s*['\"]?\$\w+",
            r"file_get_contents\s*\(\s*['\"]?\$\w+",
            r"unlink\s*\(\s*['\"]?\$\w+",
            r"rename\s*\(\s*['\"]?\$\w+",
            r"copy\s*\(\s*['\"]?\$\w+",
            r"move_uploaded_file\s*\(\s*['\"]?\$\w+"
        ],
        "description": "竞争条件漏洞，可能导致文件操作问题"
    },
    "整数溢出": {
        "cwe": "CWE-190",
        "patterns": [
            r"\$\w+\s*\+\s*\$\w+",
            r"\$\w+\s*-\s*\$\w+",
            r"\$\w+\s*\*\s*\$\w+",
            r"\$\w+\s*\/\s*\$\w+",
            r"\$\w+\s*%\s*\$\w+",
            r"intval\s*\(\s*['\"]?\$\w+",
            r"(int)\s*\$\w+",
            r"(float)\s*\$\w+",
            r"(double)\s*\$\w+",
            r"(real)\s*\$\w+"
        ],
        "description": "整数溢出漏洞，可能导致计算错误"
    },
    "缓冲区溢出": {
        "cwe": "CWE-120",
        "patterns": [
            r"strcat\s*\(\s*['\"]?\$\w+",
            r"strcpy\s*\(\s*['\"]?\$\w+",
            r"sprintf\s*\(\s*['\"]?\$\w+",
            r"vsprintf\s*\(\s*['\"]?\$\w+",
            r"snprintf\s*\(\s*['\"]?\$\w+",
            r"strncpy\s*\(\s*['\"]?\$\w+",
            r"strncat\s*\(\s*['\"]?\$\w+",
            r"memcpy\s*\(\s*['\"]?\$\w+",
            r"memmove\s*\(\s*['\"]?\$\w+"
        ],
        "description": "缓冲区溢出漏洞，可能导致内存损坏"
    },
    "越界写入": {
        "cwe": "CWE-125",
        "patterns": [
            r"\$\w+\s*\[\s*\$\w+\s*\]\s*=\s*['\"]?\$\w+",
            r"\$\w+\s*\{\s*\$\w+\s*\}\s*=\s*['\"]?\$\w+",
            r"array_push\s*\(\s*['\"]?\$\w+",
            r"array_unshift\s*\(\s*['\"]?\$\w+",
            r"array_splice\s*\(\s*['\"]?\$\w+"
        ],
        "description": "越界写入漏洞，可能导致内存损坏"
    },
    "越界读取": {
        "cwe": "CWE-125",
        "patterns": [
            r"echo\s*\$\w+\s*\[\s*\$\w+\s*\]",
            r"print\s*\$\w+\s*\[\s*\$\w+\s*\]",
            r"var_dump\s*\$\w+\s*\[\s*\$\w+\s*\]",
            r"print_r\s*\$\w+\s*\[\s*\$\w+\s*\]",
            r"json_encode\s*\(\s*\$\w+\s*\[\s*\$\w+\s*\])"
        ],
        "description": "越界读取漏洞，可能导致信息泄露"
    },
    "释放后使用": {
        "cwe": "CWE-416",
        "patterns": [
            r"unset\s*\(\s*\$\w+\s*\)",
            r"array_pop\s*\(\s*['\"]?\$\w+",
            r"array_shift\s*\(\s*['\"]?\$\w+",
            r"array_splice\s*\(\s*['\"]?\$\w+",
            r"array_slice\s*\(\s*['\"]?\$\w+"
        ],
        "description": "释放后使用漏洞，可能导致内存损坏"
    },
    "空指针解引用": {
        "cwe": "CWE-476",
        "patterns": [
            r"\$\w+\s*->\s*\$\w+",
            r"\$\w+\s*\[\s*\$\w+\s*\]",
            r"\$\w+\s*\{\s*\$\w+\s*\}",
            r"call_user_func\s*\(\s*['\"]?\$\w+",
            r"call_user_func_array\s*\(\s*['\"]?\$\w+"
        ],
        "description": "空指针解引用漏洞，可能导致程序崩溃"
    },
    "类型混淆": {
        "cwe": "CWE-843",
        "patterns": [
            r"gettype\s*\(\s*['\"]?\$\w+",
            r"is_array\s*\(\s*['\"]?\$\w+",
            r"is_string\s*\(\s*['\"]?\$\w+",
            r"is_int\s*\(\s*['\"]?\$\w+",
            r"is_float\s*\(\s*['\"]?\$\w+",
            r"is_bool\s*\(\s*['\"]?\$\w+",
            r"is_object\s*\(\s*['\"]?\$\w+",
            r"is_resource\s*\(\s*['\"]?\$\w+",
            r"is_null\s*\(\s*['\"]?\$\w+"
        ],
        "description": "类型混淆漏洞，可能导致逻辑错误"
    },
    "动态变量评估": {
        "cwe": "CWE-561",
        "patterns": [
            r"\$\$\w+",
            r"variable_get\s*\(\s*['\"]?\$\w+",
            r"variable_set\s*\(\s*['\"]?\$\w+",
            r"extract\s*\(\s*['\"]?\$\w+",
            r"compact\s*\(\s*['\"]?\$\w+"
        ],
        "description": "动态变量评估漏洞，可能导致变量覆盖"
    },
    "变量提取错误": {
        "cwe": "CWE-20",
        "patterns": [
            r"extract\s*\(\s*['\"]?\$\w+",
            r"compact\s*\(\s*['\"]?\$\w+",
            r"parse_str\s*\(\s*['\"]?\$\w+",
            r"import_request_variables\s*\(\s*['\"]?\$\w+"
        ],
        "description": "变量提取错误漏洞，可能导致变量覆盖"
    },
    "比较不正确": {
        "cwe": "CWE-571",
        "patterns": [
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?0['\"]?\s*\)",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?0['\"]?\s*\)",
            r"if\s*\(\s*\$\w+\s*===\s*['\"]?0['\"]?\s*\)",
            r"if\s*\(\s*!\s*\$\w+\s*===\s*['\"]?0['\"]?\s*\)",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)",
            r"if\s*\(\s*\$\w+\s*===\s*['\"]?false['\"]?\s*\)",
            r"if\s*\(\s*!\s*\$\w+\s*===\s*['\"]?false['\"]?\s*\)"
        ],
        "description": "比较不正确漏洞，可能导致逻辑错误"
    },
    "异常处理不当": {
        "cwe": "CWE-391",
        "patterns": [
            r"try\s*\{",
            r"catch\s*\(\s*Exception\s*\$\w+\s*\)\s*\{",
            r"finally\s*\{",
            r"throw\s*new\s*Exception\s*\(\s*['\"]?\$\w+"
        ],
        "description": "异常处理不当漏洞，可能导致信息泄露"
    },
    "缺少保护机制": {
        "cwe": "CWE-311",
        "patterns": [
            r"ini_set\s*\(\s*['\"]?disable_functions['\"]?\s*,\s*['\"]?['\"]?",
            r"ini_set\s*\(\s*['\"]?allow_url_fopen['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?allow_url_include['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?register_globals['\"]?\s*,\s*['\"]?On['\"]?"
        ],
        "description": "缺少保护机制漏洞，可能导致安全配置问题"
    },
    "无控制的递归": {
        "cwe": "CWE-674",
        "patterns": [
            r"function\s+\w+\s*\(\s*\)\s*\{",
            r"recursive\s*function\s+\w+\s*\(\s*\)\s*\{",
            r"self::\w+\(\s*\)",
            r"static::\w+\(\s*\)",
            r"\$\w+\s*=\s*call_user_func\s*\(\s*['\"]?\$\w+"
        ],
        "description": "无控制的递归漏洞，可能导致栈溢出"
    },
    "释放后使用": {
        "cwe": "CWE-416",
        "patterns": [
            r"unset\s*\(\s*\$\w+\s*\)",
            r"array_pop\s*\(\s*['\"]?\$\w+",
            r"array_shift\s*\(\s*['\"]?\$\w+",
            r"array_splice\s*\(\s*['\"]?\$\w+",
            r"array_slice\s*\(\s*['\"]?\$\w+"
        ],
        "description": "释放后使用漏洞，可能导致内存损坏"
    },
    "信任边界违反": {
        "cwe": "CWE-501",
        "patterns": [
            r"include\s*\(\s*['\"]?\$\w+",
            r"require\s*\(\s*['\"]?\$\w+",
            r"include_once\s*\(\s*['\"]?\$\w+",
            r"require_once\s*\(\s*['\"]?\$\w+",
            r"file_get_contents\s*\(\s*['\"]?\$\w+",
            r"file_put_contents\s*\(\s*['\"]?\$\w+",
            r"unlink\s*\(\s*['\"]?\$\w+",
            r"rename\s*\(\s*['\"]?\$\w+",
            r"copy\s*\(\s*['\"]?\$\w+",
            r"move_uploaded_file\s*\(\s*['\"]?\$\w+"
        ],
        "description": "信任边界违反漏洞，可能导致恶意文件操作"
    },
    "遗留调试代码": {
        "cwe": "CWE-489",
        "patterns": [
            r"var_dump\s*\(\s*\$\w+",
            r"print_r\s*\(\s*\$\w+",
            r"debug_backtrace\s*\(\s*\)",
            r"debug_print_backtrace\s*\(\s*\)",
            r"error_log\s*\(\s*['\"]?DEBUG['\"]?"
        ],
        "description": "遗留调试代码漏洞，可能导致信息泄露"
    },
    "反射型注入": {
        "cwe": "CWE-94",
        "patterns": [
            r"eval\s*\(\s*['\"]?\$\w+",
            r"assert\s*\(\s*['\"]?\$\w+",
            r"create_function\s*\(\s*['\"]?\$\w+",
            r"preg_replace\s*\(\s*['\"]?e['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "反射型注入漏洞，可能导致任意代码执行"
    },
    "嵌入恶意代码": {
        "cwe": "CWE-94",
        "patterns": [
            r"eval\s*\(\s*['\"]?\$\w+",
            r"assert\s*\(\s*['\"]?\$\w+",
            r"create_function\s*\(\s*['\"]?\$\w+",
            r"preg_replace\s*\(\s*['\"]?e['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "嵌入恶意代码漏洞，可能导致任意代码执行"
    },
    "使用弱哈希算法": {
        "cwe": "CWE-327",
        "patterns": [
            r"md5\s*\(\s*['\"]?\$\w+",
            r"sha1\s*\(\s*['\"]?\$\w+",
            r"crypt\s*\(\s*['\"]?\$\w+",
            r"hash\s*\(\s*['\"]?md5['\"]?\s*,\s*['\"]?\$\w+",
            r"hash\s*\(\s*['\"]?sha1['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "使用弱哈希算法漏洞，可能导致密码破解"
    },
    "使用已破解或有风险的加密算法": {
        "cwe": "CWE-327",
        "patterns": [
            r"md5\s*\(\s*['\"]?\$\w+",
            r"sha1\s*\(\s*['\"]?\$\w+",
            r"crypt\s*\(\s*['\"]?\$\w+",
            r"hash\s*\(\s*['\"]?md5['\"]?\s*,\s*['\"]?\$\w+",
            r"hash\s*\(\s*['\"]?sha1['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "使用已破解或有风险的加密算法漏洞，可能导致密码破解"
    },
    "硬编码加密密钥": {
        "cwe": "CWE-798",
        "patterns": [
            r"define\s*\(\s*['\"]?ENCRYPTION_KEY['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$encryption_key\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$secret_key\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$api_key\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?"
        ],
        "description": "硬编码加密密钥漏洞，可能导致密钥泄露"
    },
    "明文传输敏感信息": {
        "cwe": "CWE-319",
        "patterns": [
            r"header\s*\(\s*['\"]?Location\s*:\s*http:\/\/",
            r"header\s*\(\s*['\"]?Location\s*:\s*ftp:\/\/",
            r"header\s*\(\s*['\"]?Location\s*:\s*telnet:\/\/",
            r"header\s*\(\s*['\"]?Location\s*:\s*file:\/\/",
            r"header\s*\(\s*['\"]?Location\s*:\s*data:\/\/"
        ],
        "description": "明文传输敏感信息漏洞，可能导致信息泄露"
    },
    "明文存储敏感信息": {
        "cwe": "CWE-312",
        "patterns": [
            r"md5\s*\(\s*['\"]?\$\w+",
            r"sha1\s*\(\s*['\"]?\$\w+",
            r"crypt\s*\(\s*['\"]?\$\w+",
            r"password_hash\s*\(\s*['\"]?\$\w+",
            r"password_verify\s*\(\s*['\"]?\$\w+"
        ],
        "description": "明文存储敏感信息漏洞，可能导致信息泄露"
    },
    "未限制认证失败次数": {
        "cwe": "CWE-307",
        "patterns": [
            r"if\s*\(\s*!\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{"
        ],
        "description": "未限制认证失败次数漏洞，可能导致暴力破解"
    },
    "关键功能缺少身份认证": {
        "cwe": "CWE-285",
        "patterns": [
            r"if\s*\(\s*!\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{"
        ],
        "description": "关键功能缺少身份认证漏洞，可能导致未授权访问"
    },
    "证书验证不当": {
        "cwe": "CWE-295",
        "patterns": [
            r"curl_setopt\s*\(\s*['\"]?CURLOPT_SSL_VERIFYPEER['\"]?\s*,\s*false",
            r"curl_setopt\s*\(\s*['\"]?CURLOPT_SSL_VERIFYHOST['\"]?\s*,\s*false",
            r"stream_context_create\s*\(\s*['\"]?ssl['\"]?\s*,\s*['\"]?verify_peer['\"]?\s*=\s*false",
            r"stream_context_create\s*\(\s*['\"]?ssl['\"]?\s*,\s*['\"]?verify_peer_name['\"]?\s*=\s*false"
        ],
        "description": "证书验证不当漏洞，可能导致中间人攻击"
    },
    "身份认证不当": {
        "cwe": "CWE-287",
        "patterns": [
            r"if\s*\(\s*!\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{"
        ],
        "description": "身份认证不当漏洞，可能导致未授权访问"
    },
    "访问控制不当": {
        "cwe": "CWE-285",
        "patterns": [
            r"if\s*\(\s*!\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*empty\s*\(\s*\$\w+\s*\)\s*\{",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{"
        ],
        "description": "访问控制不当漏洞，可能导致未授权访问"
    },
    "默认权限不正确": {
        "cwe": "CWE-276",
        "patterns": [
            r"chmod\s*\(\s*['\"]?\d+['\"]?\s*,\s*['\"]?\$\w+",
            r"chmod\s*\(\s*['\"]?\$\w+\s*,\s*['\"]?\d+['\"]?",
            r"fileperms\s*\(\s*['\"]?\$\w+",
            r"fileowner\s*\(\s*['\"]?\$\w+",
            r"filegroup\s*\(\s*['\"]?\$\w+"
        ],
        "description": "默认权限不正确漏洞，可能导致权限提升"
    },
    "硬编码密码": {
        "cwe": "CWE-259",
        "patterns": [
            r"define\s*\(\s*['\"]?DB_PASSWORD['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$db_password\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$password\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$api_key\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?"
        ],
        "description": "硬编码密码漏洞，可能导致凭据泄露"
    },
    "明文存储密码": {
        "cwe": "CWE-312",
        "patterns": [
            r"md5\s*\(\s*['\"]?\$\w+",
            r"sha1\s*\(\s*['\"]?\$\w+",
            r"crypt\s*\(\s*['\"]?\$\w+",
            r"password_hash\s*\(\s*['\"]?\$\w+",
            r"password_verify\s*\(\s*['\"]?\$\w+"
        ],
        "description": "明文存储密码漏洞，可能导致密码泄露"
    },
    "不当处理多余参数": {
        "cwe": "CWE-20",
        "patterns": [
            r"parse_str\s*\(\s*['\"]?\$\w+",
            r"extract\s*\(\s*['\"]?\$\w+",
            r"compact\s*\(\s*['\"]?\$\w+",
            r"import_request_variables\s*\(\s*['\"]?\$\w+"
        ],
        "description": "不当处理多余参数漏洞，可能导致变量覆盖"
    },
    "调试信息泄露": {
        "cwe": "CWE-209",
        "patterns": [
            r"var_dump\s*\(\s*\$\w+",
            r"print_r\s*\(\s*\$\w+",
            r"debug_backtrace\s*\(\s*\)",
            r"debug_print_backtrace\s*\(\s*\)",
            r"error_log\s*\(\s*['\"]?DEBUG['\"]?"
        ],
        "description": "调试信息泄露漏洞，可能导致信息泄露"
    },
    "错误信息中的信息泄露": {
        "cwe": "CWE-209",
        "patterns": [
            r"error_reporting\s*\(\s*E_ALL\s*\)",
            r"ini_set\s*\(\s*['\"]?display_errors['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?display_startup_errors['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?log_errors['\"]?\s*,\s*['\"]?Off['\"]?",
            r"ini_set\s*\(\s*['\"]?error_log['\"]?\s*,\s*['\"]?Off['\"]?"
        ],
        "description": "错误信息中的信息泄露漏洞，可能导致信息泄露"
    },
    "可观察的响应差异": {
        "cwe": "CWE-208",
        "patterns": [
            r"if\s*\(\s*!\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{"
        ],
        "description": "可观察的响应差异漏洞，可能导致信息泄露"
    },
    "敏感信息泄露": {
        "cwe": "CWE-200",
        "patterns": [
            r"echo\s*\$\w+",
            r"print\s*\$\w+",
            r"printf\s*\$\w+",
            r"print_r\s*\$\w+",
            r"var_dump\s*\$\w+",
            r"htmlentities\s*\(\s*\$\w+\s*\)\s*;",
            r"htmlspecialchars\s*\(\s*\$\w+\s*\)\s*;",
            r"echo\s*['\"]?<\s*script\b",
            r"echo\s*['\"]?<\s*iframe\b",
            r"echo\s*['\"]?<\s*img\s+src\s*=\s*['\"]?javascript:",
            r"echo\s*['\"]?<\s*svg\s+onload\s*=\s*['\"]?javascript:",
            r"echo\s*\$\w+\s*\.?\s*html"
        ],
        "description": "敏感信息泄露漏洞，可能导致信息泄露"
    },
    "输入验证不当": {
        "cwe": "CWE-20",
        "patterns": [
            r"if\s*\(\s*!\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*empty\s*\(\s*\$\w+\s*\)\s*\{",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{"
        ],
        "description": "输入验证不当漏洞，可能导致各种注入攻击"
    },
    "配置错误": {
        "cwe": "CWE-16",
        "patterns": [
            r"ini_set\s*\(\s*['\"]?disable_functions['\"]?\s*,\s*['\"]?['\"]?",
            r"ini_set\s*\(\s*['\"]?allow_url_fopen['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?allow_url_include['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?register_globals['\"]?\s*,\s*['\"]?On['\"]?"
        ],
        "description": "配置错误漏洞，可能导致安全配置问题"
    },
    "模板注入（SSTI）": {
        "cwe": "CWE-94",
        "patterns": [
            r"eval\s*\(\s*['\"]?\$\w+",
            r"assert\s*\(\s*['\"]?\$\w+",
            r"create_function\s*\(\s*['\"]?\$\w+",
            r"preg_replace\s*\(\s*['\"]?e['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "模板注入漏洞，可能导致任意代码执行"
    },
    "正则表达式效率低下（ReDoS）": {
        "cwe": "CWE-730",
        "patterns": [
            r"preg_match\s*\(\s*['\"]?.*\*\+.*['\"]?\s*,\s*['\"]?\$\w+",
            r"preg_match_all\s*\(\s*['\"]?.*\*\+.*['\"]?\s*,\s*['\"]?\$\w+",
            r"preg_replace\s*\(\s*['\"]?.*\*\+.*['\"]?\s*,\s*['\"]?\$\w+",
            r"preg_split\s*\(\s*['\"]?.*\*\+.*['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "正则表达式效率低下漏洞，可能导致拒绝服务攻击"
    },
    "日志注入": {
        "cwe": "CWE-117",
        "patterns": [
            r"error_log\s*\(\s*['\"]?\$\w+",
            r"syslog\s*\(\s*['\"]?\$\w+",
            r"file_put_contents\s*\(\s*['\"]?php://stderr['\"]?\s*,\s*['\"]?\$\w+",
            r"file_put_contents\s*\(\s*['\"]?php://stdout['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "日志注入漏洞，可能导致日志污染"
    },
    "HTTP响应拆分": {
        "cwe": "CWE-113",
        "patterns": [
            r"header\s*\(\s*['\"]?Set-Cookie['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Location['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Content-Type['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Content-Length['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Cache-Control['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Expires['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Last-Modified['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?ETag['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Vary['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?P3P['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Content-Type-Options['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Frame-Options['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-XSS-Protection['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Content-Security-Policy['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Content-Security-Policy['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Strict-Transport-Security['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Public-Key-Pins['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Feature-Policy['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Referrer-Policy['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Expect-CT['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Permitted-Cross-Domain-Policies['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-DNS-Prefetch-Control['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Download-Options['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Content-Type-Options['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Frame-Options['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-XSS-Protection['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Content-Security-Policy['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Content-Security-Policy['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Strict-Transport-Security['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Public-Key-Pins['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Feature-Policy['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Referrer-Policy['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?Expect-CT['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Permitted-Cross-Domain-Policies['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-DNS-Prefetch-Control['\"]?\s*,\s*['\"]?\$\w+",
            r"header\s*\(\s*['\"]?X-Download-Options['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "HTTP响应拆分漏洞，可能导致响应污染"
    },
    "点击劫持": {
        "cwe": "CWE-1021",
        "patterns": [
            r"header\s*\(\s*['\"]?X-Frame-Options['\"]?\s*,\s*['\"]?DENY['\"]?",
            r"header\s*\(\s*['\"]?X-Frame-Options['\"]?\s*,\s*['\"]?SAMEORIGIN['\"]?",
            r"header\s*\(\s*['\"]?Content-Security-Policy['\"]?\s*,\s*['\"]?frame-ancestors['\"]?"
        ],
        "description": "点击劫持漏洞，可能导致UI伪装攻击"
    },
    "跨站请求伪造（CSRF）": {
        "cwe": "CWE-352",
        "patterns": [
            r"if\s*\(\s*!\s*isset\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*!\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
            r"if\s*\(\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{",
            r"if\s*\(\s*!\s*\$\w+\s*==\s*['\"]?false['\"]?\s*\)\s*\{"
        ],
        "description": "跨站请求伪造漏洞，可能导致未授权操作"
    },
    "密码签名验证不当": {
        "cwe": "CWE-347",
        "patterns": [
            r"hash_hmac\s*\(\s*['\"]?md5['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac\s*\(\s*['\"]?sha1['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac\s*\(\s*['\"]?sha256['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac\s*\(\s*['\"]?sha512['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac_file\s*\(\s*['\"]?md5['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac_file\s*\(\s*['\"]?sha1['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac_file\s*\(\s*['\"]?sha256['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac_file\s*\(\s*['\"]?sha512['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "密码签名验证不当漏洞，可能导致签名伪造"
    },
    "数据真实性验证不足": {
        "cwe": "CWE-347",
        "patterns": [
            r"hash_hmac\s*\(\s*['\"]?md5['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac\s*\(\s*['\"]?sha1['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac\s*\(\s*['\"]?sha256['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac\s*\(\s*['\"]?sha512['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac_file\s*\(\s*['\"]?md5['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac_file\s*\(\s*['\"]?sha1['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac_file\s*\(\s*['\"]?sha256['\"]?\s*,\s*['\"]?\$\w+",
            r"hash_hmac_file\s*\(\s*['\"]?sha512['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "数据真实性验证不足漏洞，可能导致数据篡改"
    },
    "使用弱伪随机数生成器": {
        "cwe": "CWE-330",
        "patterns": [
            r"rand\s*\(\s*\)",
            r"mt_rand\s*\(\s*\)",
            r"srand\s*\(\s*\)",
            r"mt_srand\s*\(\s*\)",
            r"random_int\s*\(\s*\)",
            r"random_bytes\s*\(\s*\)",
            r"openssl_random_pseudo_bytes\s*\(\s*\)"
        ],
        "description": "使用弱伪随机数生成器漏洞，可能导致随机数预测"
    },
    "使用不充分随机值": {
        "cwe": "CWE-330",
        "patterns": [
            r"rand\s*\(\s*\)",
            r"mt_rand\s*\(\s*\)",
            r"srand\s*\(\s*\)",
            r"mt_srand\s*\(\s*\)",
            r"random_int\s*\(\s*\)",
            r"random_bytes\s*\(\s*\)",
            r"openssl_random_pseudo_bytes\s*\(\s*\)"
        ],
        "description": "使用不充分随机值漏洞，可能导致随机数预测"
    },
    "未使用随机IV": {
        "cwe": "CWE-326",
        "patterns": [
            r"openssl_encrypt\s*\(\s*['\"]?\$\w+",
            r"openssl_decrypt\s*\(\s*['\"]?\$\w+",
            r"mcrypt_encrypt\s*\(\s*['\"]?\$\w+",
            r"mcrypt_decrypt\s*\(\s*['\"]?\$\w+",
            r"openssl_cipher_iv_length\s*\(\s*['\"]?\$\w+",
            r"openssl_cipher_key_length\s*\(\s*['\"]?\$\w+"
        ],
        "description": "未使用随机IV漏洞，可能导致加密强度不足"
    },
    "使用弱哈希算法": {
        "cwe": "CWE-327",
        "patterns": [
            r"md5\s*\(\s*['\"]?\$\w+",
            r"sha1\s*\(\s*['\"]?\$\w+",
            r"crypt\s*\(\s*['\"]?\$\w+",
            r"hash\s*\(\s*['\"]?md5['\"]?\s*,\s*['\"]?\$\w+",
            r"hash\s*\(\s*['\"]?sha1['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "使用弱哈希算法漏洞，可能导致密码破解"
    },
    "使用已破解或有风险的加密算法": {
        "cwe": "CWE-327",
        "patterns": [
            r"md5\s*\(\s*['\"]?\$\w+",
            r"sha1\s*\(\s*['\"]?\$\w+",
            r"crypt\s*\(\s*['\"]?\$\w+",
            r"hash\s*\(\s*['\"]?md5['\"]?\s*,\s*['\"]?\$\w+",
            r"hash\s*\(\s*['\"]?sha1['\"]?\s*,\s*['\"]?\$\w+"
        ],
        "description": "使用已破解或有风险的加密算法漏洞，可能导致密码破解"
    },
    "加密强度不足": {
        "cwe": "CWE-326",
        "patterns": [
            r"openssl_encrypt\s*\(\s*['\"]?\$\w+",
            r"openssl_decrypt\s*\(\s*['\"]?\$\w+",
            r"mcrypt_encrypt\s*\(\s*['\"]?\$\w+",
            r"mcrypt_decrypt\s*\(\s*['\"]?\$\w+",
            r"openssl_cipher_iv_length\s*\(\s*['\"]?\$\w+",
            r"openssl_cipher_key_length\s*\(\s*['\"]?\$\w+"
        ],
        "description": "加密强度不足漏洞，可能导致加密破解"
    },
    "硬编码加密密钥": {
        "cwe": "CWE-798",
        "patterns": [
            r"define\s*\(\s*['\"]?ENCRYPTION_KEY['\"]?\s*,\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$encryption_key\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$secret_key\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"\$api_key\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?"
        ],
        "description": "硬编码加密密钥漏洞，可能导致密钥泄露"
    },
    "敏感数据未加密": {
        "cwe": "CWE-312",
        "patterns": [
            r"md5\s*\(\s*['\"]?\$\w+",
            r"sha1\s*\(\s*['\"]?\$\w+",
            r"crypt\s*\(\s*['\"]?\$\w+",
            r"password_hash\s*\(\s*['\"]?\$\w+",
            r"password_verify\s*\(\s*['\"]?\$\w+"
        ],
        "description": "敏感数据未加密漏洞，可能导致数据泄露"
    },
    "错误信息中的信息泄露": {
        "cwe": "CWE-209",
        "patterns": [
            r"error_reporting\s*\(\s*E_ALL\s*\)",
            r"ini_set\s*\(\s*['\"]?display_errors['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?display_startup_errors['\"]?\s*,\s*['\"]?On['\"]?",
            r"ini_set\s*\(\s*['\"]?log_errors['\"]?\s*,\s*['\"]?Off['\"]?",
            r"ini_set\s*\(\s*['\"]?error_log['\"]?\s*,\s*['\"]?Off['\"]?"
        ],
        "description": "错误信息中的信息泄露漏洞，可能导致信息泄露"
    }
}


def calculate_md5(file_path: str) -> str:
    """计算文件的MD5值"""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()


def detect_vulnerabilities(file_path: str, content: str) -> List[Dict]:
    """检测文件中的漏洞"""
    vulnerabilities = []
    lines = content.split('\n')

    for vuln_type, rule in VULNERABILITY_RULES.items():
        for pattern in rule["patterns"]:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                start_line = content.count('\n', 0, match.start()) + 1
                end_line = content.count('\n', 0, match.end()) + 1

                vulnerabilities.append({
                    "vulnerability_type": vuln_type,
                    "cwe": rule["cwe"],
                    "description": rule["description"],
                    "start_line": start_line,
                    "end_line": end_line
                })

    return vulnerabilities


def analyze_file(file_path: str) -> Dict:
    """分析单个文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        md5 = calculate_md5(file_path)
        vulnerabilities = detect_vulnerabilities(file_path, content)

        return {
            "folder": os.path.dirname(file_path),
            "filename": os.path.basename(file_path),
            "file_path": file_path,
            "file_md5": md5,
            "has_vulnerabilities": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities
        }
    except Exception as e:
        print(f"Error analyzing file {file_path}: {str(e)}")
        return {
            "folder": os.path.dirname(file_path),
            "filename": os.path.basename(file_path),
            "file_path": file_path,
            "file_md5": "",
            "has_vulnerabilities": False,
            "vulnerabilities": []
        }


def write_results_to_csv(results: List[Dict], output_file: str):
    """将结果写入CSV文件"""
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            "folder", "filename", "file_path", "file_md5", "has_vulnerabilities",
            "vulnerability_type", "cwe", "description", "start_line", "end_line"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        for result in results:
            for vuln in result["vulnerabilities"]:
                writer.writerow({
                    "folder": result["folder"],
                    "filename": result["filename"],
                    "file_path": result["file_path"],
                    "file_md5": result["file_md5"],
                    "has_vulnerabilities": result["has_vulnerabilities"],
                    "vulnerability_type": vuln["vulnerability_type"],
                    "cwe": vuln["cwe"],
                    "description": vuln["description"],
                    "start_line": vuln["start_line"],
                    "end_line": vuln["end_line"]
                })


def call_large_model(code_snippet: str) -> Optional[Dict]:
    """调用大模型接口分析代码"""
    try:
        url = "http://localhost:8080/v1/chat/completions"
        headers = {
            "Content-Type": "application/json"
        }
        data = {
            "model": "Qwen3-Coder-30B-A3B-Instruct",
            "messages": [
                {
                    "role": "user",
                    "content": f"分析以下PHP代码中的漏洞：\n\n{code_snippet}\n\n请返回漏洞类型、CWE编号和详细描述。"
                }
            ],
            "max_tokens": 1000,
            "temperature": 0.1
        }

        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()

        if "choices" in result and len(result["choices"]) > 0:
            content = result["choices"][0]["message"]["content"]
            # 这里可以解析大模型的返回结果
            return {"analysis": content}
        return None
    except Exception as e:
        print(f"Error calling large model: {str(e)}")
        return None


def main():
    input_dir = "/data/example-s2/code1"
    output_file = "/data/example-s2/code1/result.csv"

    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    results = []

    # 遍历目录中的所有PHP文件
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith('.php'):          # 只分析 PHP 文件，可根据需要调整
                file_path = os.path.join(root, file)
                print(f"Analyzing {file_path}...")
                result = analyze_file(file_path)
                results.append(result)

    # 写入CSV
    write_results_to_csv(results, output_file)
    print(f"Results written to {output_file}")

if __name__ == "__main__":
    main()