#!/usr/bin/env python3
"""
Universal tech stack detector - finds ANY framework/technology.

Uses multiple detection strategies:
1. Dependency files (requirements.txt, package.json, etc.)
2. Import analysis (parsing actual code)
3. File structure patterns (MVC, routes, controllers)
4. Configuration files
5. Common patterns and conventions
"""

from pathlib import Path
from typing import Dict, List, Set, Optional
import re
from collections import Counter


class UniversalTechDetector:
    """Detect ANY framework/technology using intelligent pattern matching."""
    
    # Common framework indicators across languages
    FRAMEWORK_PATTERNS = {
        # Python Web Frameworks
        'flask': {'keywords': ['flask', 'from flask import', 'Flask(__name__)'], 'type': 'web_framework', 'lang': 'Python'},
        'django': {'keywords': ['django', 'from django', 'DJANGO_SETTINGS_MODULE'], 'type': 'web_framework', 'lang': 'Python'},
        'fastapi': {'keywords': ['fastapi', 'from fastapi import', 'FastAPI()'], 'type': 'web_framework', 'lang': 'Python'},
        'pyramid': {'keywords': ['pyramid', 'from pyramid'], 'type': 'web_framework', 'lang': 'Python'},
        'tornado': {'keywords': ['tornado', 'import tornado'], 'type': 'web_framework', 'lang': 'Python'},
        'bottle': {'keywords': ['bottle', 'from bottle import'], 'type': 'web_framework', 'lang': 'Python'},
        'cherrypy': {'keywords': ['cherrypy', 'import cherrypy'], 'type': 'web_framework', 'lang': 'Python'},
        'aiohttp': {'keywords': ['aiohttp', 'from aiohttp'], 'type': 'web_framework', 'lang': 'Python'},
        
        # Python ORMs/Databases
        'sqlalchemy': {'keywords': ['sqlalchemy', 'from sqlalchemy'], 'type': 'orm', 'lang': 'Python'},
        'peewee': {'keywords': ['peewee', 'from peewee'], 'type': 'orm', 'lang': 'Python'},
        'tortoise': {'keywords': ['tortoise', 'from tortoise'], 'type': 'orm', 'lang': 'Python'},
        'mongoengine': {'keywords': ['mongoengine', 'from mongoengine'], 'type': 'database', 'lang': 'Python'},
        
        # Python gRPC/APIs
        'grpc': {'keywords': ['grpc', 'import grpc', '_pb2', 'protobuf'], 'type': 'api', 'lang': 'Python'},
        'graphql': {'keywords': ['graphql', 'graphene'], 'type': 'api', 'lang': 'Python'},
        
        # JavaScript/Node.js Frameworks
        'express': {'keywords': ['express', 'require("express")', "require('express')"], 'type': 'web_framework', 'lang': 'JavaScript'},
        'koa': {'keywords': ['koa', 'require("koa")'], 'type': 'web_framework', 'lang': 'JavaScript'},
        'hapi': {'keywords': ['@hapi/hapi', 'require("@hapi'], 'type': 'web_framework', 'lang': 'JavaScript'},
        'nestjs': {'keywords': ['@nestjs/', 'NestFactory'], 'type': 'web_framework', 'lang': 'TypeScript'},
        'nextjs': {'keywords': ['next', 'next/app', 'next/router'], 'type': 'web_framework', 'lang': 'JavaScript'},
        
        # Frontend Frameworks
        'react': {'keywords': ['react', 'from "react"', 'useState', 'useEffect'], 'type': 'frontend', 'lang': 'JavaScript'},
        'vue': {'keywords': ['vue', 'from "vue"', 'createApp'], 'type': 'frontend', 'lang': 'JavaScript'},
        'angular': {'keywords': ['@angular/', 'Component', 'NgModule'], 'type': 'frontend', 'lang': 'TypeScript'},
        'svelte': {'keywords': ['svelte', '.svelte'], 'type': 'frontend', 'lang': 'JavaScript'},
        
        # Go Frameworks
        'gin': {'keywords': ['gin-gonic/gin', 'gin.Default()'], 'type': 'web_framework', 'lang': 'Go'},
        'echo': {'keywords': ['labstack/echo', 'echo.New()'], 'type': 'web_framework', 'lang': 'Go'},
        'fiber': {'keywords': ['gofiber/fiber', 'fiber.New()'], 'type': 'web_framework', 'lang': 'Go'},
        'beego': {'keywords': ['beego', 'astaxie/beego'], 'type': 'web_framework', 'lang': 'Go'},
        'revel': {'keywords': ['revel', 'revel/revel'], 'type': 'web_framework', 'lang': 'Go'},
        
        # Java Frameworks
        'spring': {'keywords': ['springframework', '@SpringBootApplication', '@RestController'], 'type': 'web_framework', 'lang': 'Java'},
        'struts': {'keywords': ['struts', 'org.apache.struts'], 'type': 'web_framework', 'lang': 'Java'},
        'play': {'keywords': ['play.mvc', 'com.typesafe.play'], 'type': 'web_framework', 'lang': 'Java'},
        'dropwizard': {'keywords': ['dropwizard', 'io.dropwizard'], 'type': 'web_framework', 'lang': 'Java'},
        
        # PHP Frameworks
        'laravel': {'keywords': ['laravel', 'Illuminate\\', 'artisan'], 'type': 'web_framework', 'lang': 'PHP'},
        'symfony': {'keywords': ['symfony', 'Symfony\\'], 'type': 'web_framework', 'lang': 'PHP'},
        'codeigniter': {'keywords': ['codeigniter', 'CI_Controller'], 'type': 'web_framework', 'lang': 'PHP'},
        'cakephp': {'keywords': ['cakephp', 'Cake\\'], 'type': 'web_framework', 'lang': 'PHP'},
        'yii': {'keywords': ['yiisoft', 'yii\\'], 'type': 'web_framework', 'lang': 'PHP'},
        
        # Ruby Frameworks
        'rails': {'keywords': ['rails', 'ActionController', 'ActiveRecord'], 'type': 'web_framework', 'lang': 'Ruby'},
        'sinatra': {'keywords': ['sinatra', 'require "sinatra"'], 'type': 'web_framework', 'lang': 'Ruby'},
        
        # .NET
        'aspnet': {'keywords': ['asp.net', 'System.Web', 'Microsoft.AspNetCore'], 'type': 'web_framework', 'lang': 'C#'},
        
        # Databases
        'postgresql': {'keywords': ['postgresql', 'psycopg2', 'pg'], 'type': 'database', 'lang': 'any'},
        'mysql': {'keywords': ['mysql', 'pymysql', 'mysql2'], 'type': 'database', 'lang': 'any'},
        'mongodb': {'keywords': ['mongodb', 'mongoose', 'pymongo'], 'type': 'database', 'lang': 'any'},
        'redis': {'keywords': ['redis', 'redis-py'], 'type': 'database', 'lang': 'any'},
        'sqlite': {'keywords': ['sqlite', 'sqlite3'], 'type': 'database', 'lang': 'any'},
        
        # C/C++ Frameworks and Build Systems
        'cmake': {'keywords': ['cmake_minimum_required', 'add_executable', 'find_package'], 'type': 'build_system', 'lang': 'C++'},
        'conan': {'keywords': ['conan', 'conans', 'ConanFile', 'conan_basic_setup'], 'type': 'package_manager', 'lang': 'C++'},
        'vcpkg': {'keywords': ['vcpkg', 'vcpkg.json'], 'type': 'package_manager', 'lang': 'C++'},
        'boost': {'keywords': ['boost/', 'boost::', '#include <boost/'], 'type': 'library', 'lang': 'C++'},
        'qt': {'keywords': ['QApplication', 'QWidget', 'Q_OBJECT', 'qt5', 'qt6'], 'type': 'framework', 'lang': 'C++'},
        'poco': {'keywords': ['Poco/', 'Poco::', 'poco-foundation'], 'type': 'library', 'lang': 'C++'},
        'grpc_cpp': {'keywords': ['grpc++', 'grpc::Server', 'grpc/grpc.h'], 'type': 'api', 'lang': 'C++'},
        'openssl_cpp': {'keywords': ['openssl', 'SSL_CTX', 'EVP_', 'openssl/ssl.h'], 'type': 'crypto', 'lang': 'C++'},

        # Testing Frameworks
        'pytest': {'keywords': ['pytest', 'import pytest'], 'type': 'testing', 'lang': 'Python'},
        'jest': {'keywords': ['jest', 'describe(', 'it('], 'type': 'testing', 'lang': 'JavaScript'},
        'mocha': {'keywords': ['mocha', 'describe(', 'it('], 'type': 'testing', 'lang': 'JavaScript'},
        'junit': {'keywords': ['junit', '@Test', 'org.junit'], 'type': 'testing', 'lang': 'Java'},
        'gtest': {'keywords': ['gtest', 'TEST_F(', 'TEST(', 'EXPECT_'], 'type': 'testing', 'lang': 'C++'},
        'catch2': {'keywords': ['catch2', 'CATCH_', 'TEST_CASE(', 'REQUIRE('], 'type': 'testing', 'lang': 'C++'},
    }
    
    @staticmethod
    def detect_all(repo_path: Path, max_files_to_scan: int = 100) -> Dict:
        """
        Universal detection - finds ANY framework/technology.
        
        Returns comprehensive tech stack information.
        """
        result = {
            'frameworks': {},  # {name: confidence_score}
            'languages': set(),
            'databases': set(),
            'testing_frameworks': set(),
            'app_type': 'unknown',
            'entry_points': [],
            'security_critical_files': [],
            'framework_specific_risks': [],
            'imports_detected': set(),
            'versions': {},
            'confidence': {}  # Detection confidence per framework
        }
        
        # 1. Scan dependency files (high confidence)
        dep_results = UniversalTechDetector._scan_dependency_files(repo_path)
        UniversalTechDetector._merge_results(result, dep_results, confidence=0.9)
        
        # 2. Scan actual code files (medium-high confidence)
        code_results = UniversalTechDetector._scan_code_files(repo_path, max_files=max_files_to_scan)
        UniversalTechDetector._merge_results(result, code_results, confidence=0.7)
        
        # 3. Analyze file structure (medium confidence)
        structure_results = UniversalTechDetector._analyze_structure(repo_path)
        UniversalTechDetector._merge_results(result, structure_results, confidence=0.5)
        
        # 4. Infer app type
        result['app_type'] = UniversalTechDetector._infer_app_type(result)
        
        # 5. Find entry points and critical files
        result['entry_points'] = UniversalTechDetector._find_entry_points(repo_path, result)
        result['security_critical_files'] = UniversalTechDetector._find_security_files(repo_path, result)
        
        # 6. Generate framework-specific risks
        result['framework_specific_risks'] = UniversalTechDetector._generate_risks(result)
        
        # 7. Detect Docker and tests
        result['has_docker'] = any([
            (repo_path / "Dockerfile").exists(),
            (repo_path / "docker-compose.yml").exists(),
            (repo_path / "docker-compose.yaml").exists(),
            len(list(repo_path.rglob("Dockerfile"))) > 0
        ])
        result['has_tests'] = any([
            (repo_path / "tests").exists(),
            (repo_path / "test").exists(),
            (repo_path / "spec").exists(),
            len(result.get('testing_frameworks', set())) > 0
        ])
        
        # 8. Build context strings
        result['languages'] = list(result['languages'])
        result['databases'] = list(result['databases'])
        result['testing_frameworks'] = list(result['testing_frameworks'])
        result['context_str'] = UniversalTechDetector._build_context(result)
        result['prompt_enhancements'] = UniversalTechDetector._build_prompt_enhancements(result)
        
        return result
    
    @staticmethod
    def _scan_dependency_files(repo_path: Path) -> Dict:
        """Scan dependency files for framework detection."""
        detected = {'frameworks': set(), 'languages': set(), 'databases': set(), 'imports': set()}
        
        # Python: requirements.txt, Pipfile, poetry.lock, setup.py
        for req_file in repo_path.rglob("requirements.txt"):
            detected['languages'].add('Python')
            try:
                content = req_file.read_text().lower()
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if fw_info['lang'] in ['Python', 'any'] and any(kw in content for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
                        if fw_info['type'] == 'database':
                            detected['databases'].add(fw_name)
            except:
                pass
        
        # Node.js: package.json
        for pkg_file in repo_path.rglob("package.json"):
            detected['languages'].add('JavaScript')
            try:
                content = pkg_file.read_text().lower()
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if fw_info['lang'] in ['JavaScript', 'TypeScript', 'any'] and any(kw in content for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
            except:
                pass
        
        # Go: go.mod
        for go_file in repo_path.rglob("go.mod"):
            detected['languages'].add('Go')
            try:
                content = go_file.read_text().lower()
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if fw_info['lang'] in ['Go', 'any'] and any(kw in content for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
            except:
                pass
        
        # Java: pom.xml, build.gradle
        for pom in repo_path.rglob("pom.xml"):
            detected['languages'].add('Java')
            try:
                content = pom.read_text().lower()
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if fw_info['lang'] in ['Java', 'any'] and any(kw in content for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
            except:
                pass
        
        # PHP: composer.json
        for composer in repo_path.rglob("composer.json"):
            detected['languages'].add('PHP')
            try:
                content = composer.read_text().lower()
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if fw_info['lang'] in ['PHP', 'any'] and any(kw in content for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
            except:
                pass
        
        # Ruby: Gemfile
        for gemfile in repo_path.rglob("Gemfile"):
            detected['languages'].add('Ruby')
            try:
                content = gemfile.read_text().lower()
                if 'rails' in content:
                    detected['frameworks'].add('rails')
                if 'sinatra' in content:
                    detected['frameworks'].add('sinatra')
            except:
                pass
        
        # C/C++: CMakeLists.txt, conanfile.txt/py, vcpkg.json
        for cmake_file in repo_path.rglob("CMakeLists.txt"):
            detected['languages'].add('C++')
            detected['frameworks'].add('cmake')
            try:
                content = cmake_file.read_text().lower()
                if 'fetchcontent' in content or 'externalproject' in content:
                    detected['frameworks'].add('cmake')
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if fw_info['lang'] in ['C++', 'any'] and any(kw.lower() in content for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
            except:
                pass
        
        for conan_file in list(repo_path.rglob("conanfile.txt")) + list(repo_path.rglob("conanfile.py")):
            detected['languages'].add('C++')
            detected['frameworks'].add('conan')
            try:
                content = conan_file.read_text().lower()
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if fw_info['lang'] in ['C++', 'any'] and any(kw.lower() in content for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
            except:
                pass
        
        for vcpkg_file in repo_path.rglob("vcpkg.json"):
            detected['languages'].add('C++')
            detected['frameworks'].add('vcpkg')
            try:
                content = vcpkg_file.read_text().lower()
                if 'boost' in content:
                    detected['frameworks'].add('boost')
                if 'openssl' in content:
                    detected['frameworks'].add('openssl_cpp')
                if 'grpc' in content:
                    detected['frameworks'].add('grpc_cpp')
            except:
                pass
        
        # Java: also check build.gradle and build.gradle.kts
        for gradle_file in list(repo_path.rglob("build.gradle")) + list(repo_path.rglob("build.gradle.kts")):
            detected['languages'].add('Java')
            try:
                content = gradle_file.read_text().lower()
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if fw_info['lang'] in ['Java', 'any'] and any(kw in content for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
            except:
                pass
        
        return detected
    
    @staticmethod
    def _scan_code_files(repo_path: Path, max_files: int = 100) -> Dict:
        """Scan actual code files to detect frameworks by imports/usage."""
        detected = {'frameworks': set(), 'languages': set(), 'imports': set()}
        
        lang_extensions = {
            '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
            '.go': 'Go', '.java': 'Java', '.php': 'PHP', '.rb': 'Ruby',
            '.cs': 'C#', '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++',
            '.c': 'C', '.h': 'C++', '.hpp': 'C++', '.hxx': 'C++',
            '.rs': 'Rust',
        }
        
        # Get code files to scan
        code_files = []
        for ext in lang_extensions.keys():
            code_files.extend(list(repo_path.rglob(f"*{ext}"))[:max_files // len(lang_extensions)])
        
        # Limit total files scanned
        code_files = code_files[:max_files]
        
        for code_file in code_files:
            # Add language
            lang = lang_extensions.get(code_file.suffix, 'Unknown')
            if lang != 'Unknown':
                detected['languages'].add(lang)
            
            try:
                content = code_file.read_text(errors='ignore')[:5000]  # First 5KB
                content_lower = content.lower()
                
                # Check for framework patterns
                for fw_name, fw_info in UniversalTechDetector.FRAMEWORK_PATTERNS.items():
                    if any(kw in content_lower for kw in fw_info['keywords']):
                        detected['frameworks'].add(fw_name)
                
                # Extract imports (Python)
                if code_file.suffix == '.py':
                    imports = re.findall(r'(?:from|import)\s+([\w.]+)', content)
                    detected['imports'].update(imports)
                
                # Extract requires (JavaScript/Node)
                if code_file.suffix in ['.js', '.ts']:
                    requires = re.findall(r'require\(["\']([^"\']+)["\']\)', content)
                    detected['imports'].update(requires)
                    imports = re.findall(r'from\s+["\']([^"\']+)["\']', content)
                    detected['imports'].update(imports)
            
            except:
                pass
        
        return detected
    
    @staticmethod
    def _analyze_structure(repo_path: Path) -> Dict:
        """Analyze file/directory structure to infer frameworks."""
        detected = {'frameworks': set(), 'patterns': []}
        
        structure_hints = {
            'django': ['manage.py', 'settings.py', 'urls.py', 'models.py'],
            'rails': ['Gemfile', 'config/routes.rb', 'app/controllers'],
            'spring': ['src/main/java', 'pom.xml', 'application.properties'],
            'laravel': ['artisan', 'app/Http/Controllers', 'routes/web.php'],
            'express': ['package.json', 'node_modules', 'routes/'],
            'cmake': ['CMakeLists.txt', 'cmake/', 'build/'],
            'conan': ['conanfile.txt', 'conanfile.py', 'CMakeLists.txt'],
        }
        
        for fw_name, indicators in structure_hints.items():
            matches = sum(1 for indicator in indicators if (repo_path / indicator).exists() or list(repo_path.rglob(indicator)))
            if matches >= 2:  # At least 2 indicators present
                detected['frameworks'].add(fw_name)
                detected['patterns'].append(f"{fw_name}: {matches}/{len(indicators)} structure indicators")
        
        return detected
    
    @staticmethod
    def _find_entry_points(repo_path: Path, tech_info: Dict) -> List[str]:
        """Find entry point files based on detected tech stack."""
        entry_points = []
        
        entry_patterns = [
            '**/routes.py', '**/routes.js', '**/router.js', '**/router.go',
            '**/app.py', '**/main.py', '**/server.py', '**/api.py',
            '**/app.js', '**/server.js', '**/index.js', '**/main.js',
            '**/main.go', '**/*Handler.go', '**/*Router.go',
            '**/*Controller.java', '**/*Controller.php', '**/*Controller.py',
            '**/views.py', '**/endpoints.py', '**/handlers.py',
            '**/main.cpp', '**/main.c', '**/*server*.cpp', '**/*socket*.cpp',
            '**/*handler*.cpp', '**/*service*.cpp',
        ]
        
        for pattern in entry_patterns:
            for f in repo_path.glob(pattern):
                if f.is_file():
                    try:
                        entry_points.append(str(f.relative_to(repo_path)))
                    except:
                        pass
        
        return list(set(entry_points))[:50]  # Limit to 50
    
    @staticmethod
    def _find_security_files(repo_path: Path, tech_info: Dict) -> List[str]:
        """Find security-critical files."""
        security_files = []
        
        security_patterns = [
            '**/*auth*.py', '**/*login*.py', '**/*session*.py', '**/*token*.py',
            '**/*auth*.js', '**/*login*.js', '**/*session*.js', '**/*token*.js',
            '**/*auth*.go', '**/*login*.go', '**/*session*.go',
            '**/*Auth*.java', '**/*Login*.java', '**/*Security*.java',
            '**/*auth*.php', '**/*login*.php', '**/*session*.php',
            '**/config.py', '**/settings.py', '**/config.js', '**/config.php',
            '**/middleware*.py', '**/middleware*.js', '**/middleware*.go',
            '**/*crypto*.cpp', '**/*crypto*.h', '**/*auth*.cpp', '**/*auth*.h',
            '**/*ssl*.cpp', '**/*tls*.cpp', '**/*buffer*.cpp', '**/*parser*.cpp',
        ]
        
        for pattern in security_patterns:
            for f in repo_path.glob(pattern):
                if f.is_file():
                    try:
                        security_files.append(str(f.relative_to(repo_path)))
                    except:
                        pass
        
        return list(set(security_files))[:50]  # Limit to 50
    
    @staticmethod
    def _generate_risks(tech_info: Dict) -> List[str]:
        """Generate framework-specific security risks."""
        risks = []
        
        # Framework-specific risk database
        framework_risks = {
            'flask': [
                'Flask Debug Mode enabled (app.run(debug=True))',
                'Weak SECRET_KEY configuration',
                'SSTI (Server-Side Template Injection) via Jinja2',
                'Insecure session cookie settings',
                'Missing CSRF protection'
            ],
            'django': [
                'DEBUG=True in production',
                'SECRET_KEY exposed or weak',
                'SQL injection via raw() queries',
                'Mass assignment via ModelForms',
                'CSRF token validation bypass'
            ],
            'express': [
                'Missing helmet.js security headers',
                'Middleware order vulnerabilities',
                'Prototype pollution attacks',
                'Missing input validation',
                'Insecure session configuration'
            ],
            'spring': [
                'Spring Actuator endpoints exposed',
                'SpEL (Spring Expression Language) injection',
                'Mass assignment via @RequestBody',
                'Insecure deserialization',
                'Missing security headers'
            ],
            'laravel': [
                'Mass assignment vulnerabilities',
                'Eloquent SQL injection via whereRaw()',
                'Blade template injection',
                'Insecure session configuration'
            ],
            'sqlalchemy': [
                'Raw SQL injection via text() or execute()',
                'Unsafe query construction',
                'SQL injection via filter concatenation'
            ],
            'grpc': [
                'Missing authentication/authorization',
                'Unvalidated protobuf message fields',
                'Insecure channel configuration',
                'Missing rate limiting'
            ],
            'react': [
                'XSS via dangerouslySetInnerHTML',
                'Exposed API keys in frontend code',
                'Client-side auth bypass',
                'Insecure localStorage usage'
            ]
        }
        
        for fw in tech_info.get('frameworks', {}):
            if fw in framework_risks:
                risks.extend(framework_risks[fw])
        
        # C/C++ build-system / library risks
        cpp_risks = {
            'cmake': [
                'CMake FetchContent / ExternalProject without hash pinning',
                'CMake: insecure add_custom_command with user-controlled input',
                'CMake: missing hardening flags (-fstack-protector, -D_FORTIFY_SOURCE)',
            ],
            'conan': [
                'Conan: unpinned dependency versions',
                'Conan: dependencies fetched over HTTP instead of HTTPS',
                'Conan: missing integrity verification for packages',
            ],
            'boost': [
                'Boost.Asio: unchecked buffer sizes in async reads',
                'Boost.Serialization: deserialization of untrusted data',
            ],
            'openssl_cpp': [
                'OpenSSL: deprecated cipher suites or protocol versions',
                'OpenSSL: missing certificate validation',
                'OpenSSL: insecure random number generation',
            ],
        }
        for fw, fw_risks in cpp_risks.items():
            if fw in tech_info.get('frameworks', {}):
                risks.extend(fw_risks)

        # Generic risks based on languages
        if 'Python' in tech_info.get('languages', []):
            risks.append('Python: eval(), exec(), pickle.loads() code execution')
        if 'JavaScript' in tech_info.get('languages', []) or 'TypeScript' in tech_info.get('languages', []):
            risks.append('JavaScript: eval(), new Function() code execution')
        if 'PHP' in tech_info.get('languages', []):
            risks.extend(['PHP: system(), shell_exec() command injection', 'PHP: unserialize() object injection'])
        if 'C++' in tech_info.get('languages', []) or 'C' in tech_info.get('languages', []):
            risks.extend([
                'C/C++: Buffer overflow via strcpy/strcat/sprintf/gets (CWE-120)',
                'C/C++: Use-after-free and double-free (CWE-416/415)',
                'C/C++: Format string vulnerabilities (CWE-134)',
                'C/C++: Integer overflow in size calculations (CWE-190)',
                'C/C++: Null pointer dereference (CWE-476)',
            ])
        
        return list(set(risks))
    
    @staticmethod
    def _merge_results(target: Dict, source: Dict, confidence: float):
        """Merge detection results with confidence weighting."""
        if 'frameworks' in source:
            for fw in source['frameworks']:
                if fw not in target['frameworks']:
                    target['frameworks'][fw] = confidence
                else:
                    # Increase confidence if detected multiple ways
                    target['frameworks'][fw] = min(1.0, target['frameworks'][fw] + confidence * 0.3)
        
        if 'languages' in source:
            target['languages'].update(source['languages'])
        
        if 'databases' in source:
            target['databases'].update(source['databases'])
        
        if 'imports' in source:
            target['imports_detected'].update(source['imports'])
    
    @staticmethod
    def _infer_app_type(tech_info: Dict) -> str:
        """Infer application type from detected tech."""
        frameworks = tech_info.get('frameworks', {})
        
        # Check for API frameworks
        api_frameworks = {'fastapi', 'grpc', 'graphql', 'express'}
        if any(fw in frameworks for fw in api_frameworks):
            return 'web_api'
        
        # Check for web frameworks
        web_frameworks = {'flask', 'django', 'laravel', 'spring', 'rails'}
        if any(fw in frameworks for fw in web_frameworks):
            return 'web_app'
        
        # Check for frontend
        frontend_frameworks = {'react', 'vue', 'angular', 'svelte'}
        if any(fw in frameworks for fw in frontend_frameworks):
            return 'frontend_app'
        
        # Check for microservice indicators
        if 'grpc' in frameworks or 'mongodb' in frameworks:
            return 'microservice'
        
        # Check for native / C++ applications
        native_indicators = {'cmake', 'conan', 'vcpkg', 'boost', 'qt'}
        if any(fw in frameworks for fw in native_indicators):
            return 'native_app'
        
        return 'unknown'
    
    @staticmethod
    def _build_context(result: Dict) -> str:
        """Build context string for AI."""
        lines = []
        
        # Sort frameworks by confidence
        frameworks_sorted = sorted(
            result['frameworks'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        fw_names = [f[0] for f in frameworks_sorted]
        
        lines.append(f"Application Type: {result['app_type']}")
        lines.append(f"Frameworks: {', '.join(fw_names) if fw_names else 'Unknown'}")
        lines.append(f"Languages: {', '.join(result['languages'])}")
        
        if result['databases']:
            lines.append(f"Databases: {', '.join(result['databases'])}")
        
        if result['entry_points']:
            lines.append(f"Entry Points: {len(result['entry_points'])} detected")
        
        if result['security_critical_files']:
            lines.append(f"Security-Critical Files: {len(result['security_critical_files'])} detected")
        
        return "\n".join(lines)
    
    @staticmethod
    def _build_prompt_enhancements(result: Dict) -> str:
        """Build framework-specific prompt enhancements."""
        lines = []
        
        if result['framework_specific_risks']:
            lines.append("\nFRAMEWORK-SPECIFIC SECURITY RISKS:")
            for risk in result['framework_specific_risks'][:15]:
                lines.append(f"  • {risk}")
        
        if result['entry_points']:
            lines.append(f"\nENTRY POINTS ({len(result['entry_points'])} detected):")
            for ep in result['entry_points'][:5]:
                lines.append(f"  • {ep}")
            if len(result['entry_points']) > 5:
                lines.append(f"  ... and {len(result['entry_points']) - 5} more")
        
        if result['security_critical_files']:
            lines.append(f"\nSECURITY-CRITICAL FILES ({len(result['security_critical_files'])} detected):")
            for sf in result['security_critical_files'][:5]:
                lines.append(f"  • {sf}")
            if len(result['security_critical_files']) > 5:
                lines.append(f"  ... and {len(result['security_critical_files']) - 5} more")
        
        return "\n".join(lines)

