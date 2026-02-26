#!/usr/bin/env python3
"""
Enhanced tech stack detection for framework-aware security analysis.

Detects:
- Frameworks and versions
- Entry points (routes, controllers, APIs)
- Critical security files (auth, config, middleware)
- Dependencies with known vulnerabilities
- Database types and ORMs
"""

from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
import re
import json


class EnhancedTechDetector:
    """Advanced technology stack detection with security focus."""
    
    @staticmethod
    def detect_full_stack(repo_path: Path) -> Dict[str, any]:
        """
        Comprehensive tech stack detection.
        
        Returns enriched context including:
        - frameworks: Detected frameworks with versions
        - languages: Primary languages
        - entry_points: Critical files (routes, controllers, auth)
        - databases: Database types and ORMs
        - known_vulns: Dependencies with known vulnerabilities
        - security_critical_files: Auth, config, middleware files
        - framework_specific_risks: Known attack patterns for this stack
        """
        result = {
            'frameworks': [],
            'languages': set(),
            'app_type': 'unknown',
            'entry_points': [],
            'databases': [],
            'security_critical_files': [],
            'framework_specific_risks': [],
            'versions': {},
            'has_docker': False,
            'has_tests': False
        }
        
        # Python detection
        python_info = EnhancedTechDetector._detect_python(repo_path)
        if python_info:
            result['languages'].add('Python')
            result['frameworks'].extend(python_info['frameworks'])
            result['entry_points'].extend(python_info['entry_points'])
            result['databases'].extend(python_info['databases'])
            result['security_critical_files'].extend(python_info['security_files'])
            result['framework_specific_risks'].extend(python_info['risks'])
            result['versions'].update(python_info['versions'])
            if python_info['app_type'] != 'unknown':
                result['app_type'] = python_info['app_type']
        
        # Node.js detection
        node_info = EnhancedTechDetector._detect_nodejs(repo_path)
        if node_info:
            result['languages'].add('JavaScript/TypeScript')
            result['frameworks'].extend(node_info['frameworks'])
            result['entry_points'].extend(node_info['entry_points'])
            result['security_critical_files'].extend(node_info['security_files'])
            result['framework_specific_risks'].extend(node_info['risks'])
            result['versions'].update(node_info['versions'])
            if node_info['app_type'] != 'unknown':
                result['app_type'] = node_info['app_type']
        
        # Go detection
        go_info = EnhancedTechDetector._detect_go(repo_path)
        if go_info:
            result['languages'].add('Go')
            result['frameworks'].extend(go_info['frameworks'])
            result['entry_points'].extend(go_info['entry_points'])
            result['framework_specific_risks'].extend(go_info['risks'])
            if go_info['app_type'] != 'unknown':
                result['app_type'] = go_info['app_type']
        
        # Java detection
        java_info = EnhancedTechDetector._detect_java(repo_path)
        if java_info:
            result['languages'].add('Java')
            result['frameworks'].extend(java_info['frameworks'])
            result['entry_points'].extend(java_info['entry_points'])
            result['security_critical_files'].extend(java_info['security_files'])
            result['framework_specific_risks'].extend(java_info['risks'])
            if java_info['app_type'] != 'unknown':
                result['app_type'] = java_info['app_type']
        
        # PHP detection
        php_info = EnhancedTechDetector._detect_php(repo_path)
        if php_info:
            result['languages'].add('PHP')
            result['frameworks'].extend(php_info['frameworks'])
            result['entry_points'].extend(php_info['entry_points'])
            result['security_critical_files'].extend(php_info['security_files'])
            result['framework_specific_risks'].extend(php_info['risks'])
            if php_info['app_type'] != 'unknown':
                result['app_type'] = php_info['app_type']
        
        # C/C++ detection
        cpp_info = EnhancedTechDetector._detect_cpp(repo_path)
        if cpp_info:
            result['languages'].add('C++')
            result['frameworks'].extend(cpp_info['frameworks'])
            result['entry_points'].extend(cpp_info['entry_points'])
            result['security_critical_files'].extend(cpp_info['security_files'])
            result['framework_specific_risks'].extend(cpp_info['risks'])
            if cpp_info['app_type'] != 'unknown':
                result['app_type'] = cpp_info['app_type']
        
        # Docker/container detection
        result['has_docker'] = (repo_path / "Dockerfile").exists() or (repo_path / "docker-compose.yml").exists()
        
        # Test presence
        result['has_tests'] = any([
            (repo_path / "tests").exists(),
            (repo_path / "test").exists(),
            (repo_path / "spec").exists()
        ])
        
        # Convert set to list for JSON serialization
        result['languages'] = list(result['languages'])
        
        # Generate framework-aware context string
        result['context_str'] = EnhancedTechDetector._build_context_string(result)
        result['prompt_enhancements'] = EnhancedTechDetector._build_prompt_enhancements(result)
        
        return result
    
    @staticmethod
    def _detect_python(repo_path: Path) -> Optional[Dict]:
        """Detect Python frameworks and critical files."""
        # Search recursively for requirements.txt
        requirements_files = list(repo_path.rglob("requirements.txt"))
        if not requirements_files:
            return None
        
        info = {
            'frameworks': [],
            'entry_points': [],
            'databases': [],
            'security_files': [],
            'risks': [],
            'versions': {},
            'app_type': 'unknown'
        }
        
        try:
            # Combine content from all requirements files
            content = "\n".join(req.read_text().lower() for req in requirements_files)
            
            # Flask detection
            if 'flask' in content:
                info['frameworks'].append('Flask')
                info['app_type'] = 'web_app'
                info['risks'].extend([
                    'Flask Debug Mode (check for app.run(debug=True))',
                    'Flask Session Security (check secret_key strength)',
                    'SSTI via Jinja2 templates',
                    'SQLAlchemy injection via raw SQL'
                ])
                # Find Flask entry points
                info['entry_points'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*')
                    if f.is_file() and f.name in ['app.py', 'routes.py', '__init__.py', 'views.py']
                ])
                info['security_files'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*')
                    if f.is_file() and f.name in ['config.py', 'auth.py', 'login.py', 'middleware.py']
                ])
                
                if 'sqlalchemy' in content:
                    info['databases'].append('SQLAlchemy')
                    info['risks'].append('SQLAlchemy: Raw SQL injection, unsafe query construction')
            
            # Django detection
            if 'django' in content:
                info['frameworks'].append('Django')
                info['app_type'] = 'web_app'
                info['risks'].extend([
                    'Django Debug Mode (check DEBUG=True in settings)',
                    'Django SQL injection via raw queries',
                    'Mass assignment via ModelForms',
                    'CSRF token bypass'
                ])
                info['entry_points'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*')
                    if f.is_file() and f.name in ['views.py', 'urls.py', 'models.py']
                ])
                info['security_files'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*')
                    if f.is_file() and f.name in ['settings.py', 'auth.py', 'middleware.py']
                ])
            
            # FastAPI detection
            if 'fastapi' in content:
                info['frameworks'].append('FastAPI')
                info['app_type'] = 'web_api'
                info['risks'].extend([
                    'FastAPI: Pydantic validation bypass',
                    'Async race conditions',
                    'Mass assignment via Pydantic models'
                ])
                info['entry_points'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*')
                    if f.is_file() and f.name in ['main.py', 'routes.py', 'api.py']
                ])
            
            # gRPC detection
            if 'grpc' in content or 'protobuf' in content:
                info['frameworks'].append('gRPC')
                if not info['app_type'] or info['app_type'] == 'unknown':
                    info['app_type'] = 'microservice'
                info['risks'].extend([
                    'gRPC: Missing authentication/authorization',
                    'Protobuf deserialization issues',
                    'Unvalidated message fields'
                ])
                info['entry_points'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*')
                    if f.is_file() and ('_pb2' in f.name or 'grpc' in f.name.lower())
                ])
        
        except Exception:
            pass
        
        return info if info['frameworks'] else None
    
    @staticmethod
    def _detect_nodejs(repo_path: Path) -> Optional[Dict]:
        """Detect Node.js frameworks and critical files."""
        # Search recursively for package.json
        package_files = list(repo_path.rglob("package.json"))
        if not package_files:
            return None
        
        info = {
            'frameworks': [],
            'entry_points': [],
            'security_files': [],
            'risks': [],
            'versions': {},
            'app_type': 'unknown'
        }
        
        try:
            # Combine content from all package.json files
            content = "\n".join(pkg.read_text().lower() for pkg in package_files)
            
            # Express detection
            if 'express' in content:
                info['frameworks'].append('Express')
                info['app_type'] = 'web_api'
                info['risks'].extend([
                    'Express: Missing helmet.js security headers',
                    'Middleware order vulnerabilities',
                    'Mass assignment via req.body',
                    'Prototype pollution'
                ])
                info['entry_points'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*')
                    if f.is_file() and f.name in ['server.js', 'app.js', 'index.js', 'routes.js']
                ])
                info['security_files'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*')
                    if f.is_file() and ('auth' in f.name.lower() or 'middleware' in f.name.lower())
                ])
            
            # React detection
            if 'react' in content:
                info['frameworks'].append('React')
                info['risks'].extend([
                    'React: XSS via dangerouslySetInnerHTML',
                    'Client-side auth bypass',
                    'Exposed API keys in frontend'
                ])
            
            # Vue detection
            if 'vue' in content:
                info['frameworks'].append('Vue')
                info['risks'].extend([
                    'Vue: XSS via v-html',
                    'Client-side validation only'
                ])
        
        except Exception:
            pass
        
        return info if info['frameworks'] else None
    
    @staticmethod
    def _detect_go(repo_path: Path) -> Optional[Dict]:
        """Detect Go frameworks."""
        go_mod = repo_path / "go.mod"
        if not go_mod.exists():
            return None
        
        info = {
            'frameworks': [],
            'entry_points': [],
            'risks': [],
            'app_type': 'unknown'
        }
        
        try:
            content = go_mod.read_text().lower()
            
            if 'gin' in content or 'echo' in content or 'fiber' in content:
                info['frameworks'].append('Go Web Framework')
                info['app_type'] = 'web_api'
                info['risks'].extend([
                    'Go: SQL injection via string concatenation',
                    'Command injection via exec.Command',
                    'Path traversal in file operations'
                ])
                info['entry_points'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*.go')
                    if f.is_file() and ('main.go' in f.name or 'router' in f.name.lower() or 'handler' in f.name.lower())
                ])
        
        except Exception:
            pass
        
        return info if info['frameworks'] else None
    
    @staticmethod
    def _detect_java(repo_path: Path) -> Optional[Dict]:
        """Detect Java frameworks (pom.xml AND build.gradle/build.gradle.kts)."""
        build_files = []
        pom_xml = repo_path / "pom.xml"
        if pom_xml.exists():
            build_files.append(pom_xml)
        for gradle_name in ("build.gradle", "build.gradle.kts"):
            gf = repo_path / gradle_name
            if gf.exists():
                build_files.append(gf)
            build_files.extend(repo_path.rglob(gradle_name))
        
        if not build_files:
            return None
        
        info = {
            'frameworks': [],
            'entry_points': [],
            'security_files': [],
            'risks': [],
            'app_type': 'unknown'
        }
        
        try:
            content = "\n".join(bf.read_text().lower() for bf in build_files)
            
            if 'spring' in content:
                info['frameworks'].append('Spring Boot')
                info['app_type'] = 'web_app'
                info['risks'].extend([
                    'Spring: Actuator endpoints exposed',
                    'Spring Expression Language (SpEL) injection',
                    'Mass assignment via @RequestBody',
                    'JPA/Hibernate injection',
                    'Spring Security filter-chain misconfiguration',
                    'CORS / CSRF misconfiguration in Spring Security',
                ])
                info['entry_points'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*.java')
                    if f.is_file() and ('Controller' in f.name or 'RestController' in f.name or 'Repository' in f.name)
                ])
                info['security_files'].extend([
                    str(f.relative_to(repo_path)) for f in repo_path.rglob('*.java')
                    if f.is_file() and ('Security' in f.name or 'Auth' in f.name or 'Config' in f.name)
                ])
                # Also pick up application.yml / application.properties
                for cfg_pattern in ['application.yml', 'application.properties', 'application-*.yml']:
                    info['security_files'].extend([
                        str(f.relative_to(repo_path)) for f in repo_path.rglob(cfg_pattern)
                        if f.is_file()
                    ])
        
        except Exception:
            pass
        
        return info if info['frameworks'] else None
    
    @staticmethod
    def _detect_cpp(repo_path: Path) -> Optional[Dict]:
        """Detect C/C++ build systems, libraries, and security-critical files."""
        cmake_files = list(repo_path.rglob("CMakeLists.txt"))
        conan_files = list(repo_path.rglob("conanfile.txt")) + list(repo_path.rglob("conanfile.py"))
        vcpkg_files = list(repo_path.rglob("vcpkg.json"))
        
        has_cpp = bool(cmake_files or conan_files or vcpkg_files or list(repo_path.rglob("*.cpp"))[:1])
        if not has_cpp:
            return None
        
        info = {
            'frameworks': [],
            'entry_points': [],
            'security_files': [],
            'risks': [],
            'app_type': 'native_app'
        }
        
        if cmake_files:
            info['frameworks'].append('CMake')
        if conan_files:
            info['frameworks'].append('Conan')
        if vcpkg_files:
            info['frameworks'].append('vcpkg')
        
        try:
            all_build_content = ""
            for bf in (cmake_files + conan_files + vcpkg_files)[:10]:
                all_build_content += bf.read_text(errors='ignore').lower() + "\n"
            
            if 'boost' in all_build_content:
                info['frameworks'].append('Boost')
            if 'openssl' in all_build_content:
                info['frameworks'].append('OpenSSL')
            if 'grpc' in all_build_content or 'protobuf' in all_build_content:
                info['frameworks'].append('gRPC-C++')
            if 'qt' in all_build_content:
                info['frameworks'].append('Qt')
            if 'poco' in all_build_content:
                info['frameworks'].append('Poco')
            
            if 'fetchcontent' in all_build_content or 'externalproject' in all_build_content:
                info['risks'].append('CMake FetchContent/ExternalProject without hash pinning')
            
            info['risks'].extend([
                'C/C++: Buffer overflow via strcpy/strcat/sprintf/gets (CWE-120)',
                'C/C++: Use-after-free (CWE-416) and double-free (CWE-415)',
                'C/C++: Format string vulnerabilities (CWE-134)',
                'C/C++: Integer overflow in size calculations (CWE-190)',
            ])
            
            if conan_files:
                info['risks'].append('Conan: Unpinned dependency versions or HTTP-only remotes')
            
        except Exception:
            pass
        
        cpp_extensions = {'.cpp', '.cc', '.cxx', '.c', '.h', '.hpp', '.hxx'}
        for f in repo_path.rglob('*'):
            if not f.is_file() or f.suffix not in cpp_extensions:
                continue
            fname_lower = f.name.lower()
            try:
                rel = str(f.relative_to(repo_path))
            except ValueError:
                continue
            if fname_lower.startswith('main.') or 'server' in fname_lower or 'socket' in fname_lower or 'handler' in fname_lower:
                info['entry_points'].append(rel)
            if any(kw in fname_lower for kw in ['crypto', 'ssl', 'tls', 'auth', 'token', 'password', 'buffer', 'parser', 'alloc']):
                info['security_files'].append(rel)
        
        info['entry_points'] = list(set(info['entry_points']))[:50]
        info['security_files'] = list(set(info['security_files']))[:50]
        
        return info
    
    @staticmethod
    def _detect_php(repo_path: Path) -> Optional[Dict]:
        """Detect PHP frameworks."""
        info = {
            'frameworks': [],
            'entry_points': [],
            'security_files': [],
            'risks': [],
            'app_type': 'unknown'
        }
        
        # Check for composer.json
        composer_json = repo_path / "composer.json"
        if composer_json.exists():
            try:
                content = composer_json.read_text().lower()
                
                if 'laravel' in content:
                    info['frameworks'].append('Laravel')
                    info['app_type'] = 'web_app'
                    info['risks'].extend([
                        'Laravel: Mass assignment vulnerabilities',
                        'Eloquent SQL injection via whereRaw',
                        'Blade template injection'
                    ])
                    info['entry_points'].extend([
                        str(f.relative_to(repo_path)) for f in repo_path.rglob('*.php')
                        if f.is_file() and ('Controller' in f.name or 'routes' in f.name.lower())
                    ])
                
                if 'symfony' in content:
                    info['frameworks'].append('Symfony')
                    info['app_type'] = 'web_app'
                    info['risks'].extend([
                        'Symfony: Twig SSTI vulnerabilities',
                        'Doctrine ORM injection'
                    ])
            except Exception:
                pass
        
        # Generic PHP detection (look for common files)
        php_files = list(repo_path.rglob('*.php'))
        if php_files:
            if not info['frameworks']:
                info['frameworks'].append('PHP')
                info['app_type'] = 'web_app'
            
            # Find security-critical PHP files
            for f in php_files[:50]:  # Limit to avoid performance issues
                fname_lower = f.name.lower()
                if any(keyword in fname_lower for keyword in ['login', 'auth', 'session', 'token', 'config']):
                    try:
                        info['security_files'].append(str(f.relative_to(repo_path)))
                    except ValueError:
                        pass
                if any(keyword in fname_lower for keyword in ['index', 'router', 'controller', 'api']):
                    try:
                        info['entry_points'].append(str(f.relative_to(repo_path)))
                    except ValueError:
                        pass
            
            info['risks'].extend([
                'PHP: SQL injection via mysqli/PDO',
                'Command injection via shell_exec/system',
                'File inclusion vulnerabilities',
                'Insecure deserialization (unserialize)'
            ])
        
        return info if info['frameworks'] or php_files else None
    
    @staticmethod
    def _build_context_string(result: Dict) -> str:
        """Build rich context string for AI prompts."""
        lines = []
        lines.append(f"Application Type: {result['app_type']}")
        lines.append(f"Frameworks: {', '.join(result['frameworks']) if result['frameworks'] else 'Unknown'}")
        lines.append(f"Languages: {', '.join(result['languages'])}")
        
        if result['databases']:
            lines.append(f"Databases/ORMs: {', '.join(result['databases'])}")
        
        if result['entry_points']:
            count = len(result['entry_points'])
            lines.append(f"Entry Points Detected: {count} files (routes, controllers, APIs)")
        
        if result['security_critical_files']:
            count = len(result['security_critical_files'])
            lines.append(f"Security-Critical Files: {count} (auth, config, middleware)")
        
        if result['has_docker']:
            lines.append("Containerized: Yes (Docker detected)")
        
        return "\n".join(lines)
    
    @staticmethod
    def _build_prompt_enhancements(result: Dict) -> str:
        """Build framework-specific prompt enhancements."""
        if not result['framework_specific_risks']:
            return ""
        
        lines = []
        lines.append("\nFRAMEWORK-SPECIFIC SECURITY RISKS TO PRIORITIZE:")
        for risk in result['framework_specific_risks'][:10]:  # Top 10 risks
            lines.append(f"  • {risk}")
        
        if result['entry_points']:
            lines.append(f"\nCRITICAL ENTRY POINTS TO ANALYZE ({len(result['entry_points'])} detected):")
            for ep in result['entry_points'][:5]:  # Show first 5
                lines.append(f"  • {ep}")
            if len(result['entry_points']) > 5:
                lines.append(f"  ... and {len(result['entry_points']) - 5} more")
        
        if result['security_critical_files']:
            lines.append(f"\nSECURITY-CRITICAL FILES ({len(result['security_critical_files'])} detected):")
            for sf in result['security_critical_files'][:5]:  # Show first 5
                lines.append(f"  • {sf}")
            if len(result['security_critical_files']) > 5:
                lines.append(f"  ... and {len(result['security_critical_files']) - 5} more")
        
        return "\n".join(lines)


def generate_framework_aware_prioritization_question(
    original_question: str,
    tech_info: Dict
) -> str:
    """
    Enhance prioritization question with framework context.
    
    Example:
      Original: "find security vulnerabilities"
      Enhanced: "find security vulnerabilities, focusing on Flask SQLAlchemy injection, 
                 session management issues, and SSTI in Jinja2 templates. Prioritize
                 routes.py, auth.py, and config.py files."
    """
    if not tech_info or not tech_info.get('frameworks'):
        return original_question
    
    enhancements = []
    
    # Add framework-specific focus
    if tech_info.get('framework_specific_risks'):
        risk_focus = ", ".join(tech_info['framework_specific_risks'][:3])
        enhancements.append(f"focusing on {risk_focus}")
    
    # Add critical file focus
    if tech_info.get('security_critical_files'):
        files = [Path(f).name for f in tech_info['security_critical_files'][:5]]
        enhancements.append(f"Prioritize files: {', '.join(files)}")
    
    if enhancements:
        return f"{original_question}, {'. '.join(enhancements)}"
    
    return original_question

