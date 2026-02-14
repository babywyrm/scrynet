#!/usr/bin/env python3
"""
Configuration presets and smart defaults for Agent Smith.

Provides preset configurations for common use cases and smart defaults
that adapt based on scan context.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class ScanPreset:
    """Preset configuration for common scanning scenarios."""
    name: str
    description: str
    profiles: List[str]
    prioritize: bool
    prioritize_top: int
    generate_payloads: bool
    annotate_code: bool
    deduplicate: bool
    dedupe_threshold: float
    dedupe_strategy: str
    top_n: int
    export_formats: List[str]
    threat_model: bool = False
    parallel: bool = False
    show_quick_wins: bool = False  # Display quick win summary
    show_chains: bool = False  # Enable cross-file taint tracking
    
    def to_dict(self) -> dict:
        """Convert preset to dictionary for merging with args."""
        return {
            'profiles': ','.join(self.profiles),
            'prioritize': self.prioritize,
            'prioritize_top': self.prioritize_top,
            'generate_payloads': self.generate_payloads,
            'annotate_code': self.annotate_code,
            'deduplicate': self.deduplicate,
            'dedupe_threshold': self.dedupe_threshold,
            'dedupe_strategy': self.dedupe_strategy,
            'top_n': self.top_n,
            'export_format': self.export_formats,
            'threat_model': self.threat_model,
            'parallel': self.parallel,
            'show_quick_wins': self.show_quick_wins,
            'show_chains': self.show_chains
        }


# ============================================================================
# Preset Configurations
# ============================================================================

PRESETS: Dict[str, ScanPreset] = {
    'mcp': ScanPreset(
        name='mcp',
        description='MCP-optimized: 2 files, no payloads/annotations (~1 min)',
        profiles=['owasp'],
        prioritize=True,
        prioritize_top=2,
        generate_payloads=False,
        annotate_code=False,
        deduplicate=True,
        dedupe_threshold=0.7,
        dedupe_strategy='keep_highest_severity',
        top_n=0,
        export_formats=['json'],
        parallel=True
    ),
    
    'quick': ScanPreset(
        name='quick',
        description='Fast scan for CI/CD pipelines (10-15 prioritized files, JSON only)',
        profiles=['owasp'],
        prioritize=True,
        prioritize_top=10,
        generate_payloads=False,
        annotate_code=False,
        deduplicate=True,
        dedupe_threshold=0.7,
        dedupe_strategy='keep_highest_severity',
        top_n=3,
        export_formats=['json'],
        parallel=True  # Fast execution
    ),
    
    'ctf': ScanPreset(
        name='ctf',
        description='CTF-focused scan (exploitable vulns, payloads, 15 files)',
        profiles=['ctf', 'owasp'],
        prioritize=True,
        prioritize_top=15,
        generate_payloads=True,
        annotate_code=True,
        deduplicate=True,
        dedupe_threshold=0.7,
        dedupe_strategy='keep_highest_severity',
        top_n=5,
        export_formats=['json', 'html', 'markdown'],
        show_quick_wins=True  # CTF mode shows quick wins
    ),
    
    'ctf-fast': ScanPreset(
        name='ctf-fast',
        description='Quick CTF scan (8 files, payloads only)',
        profiles=['ctf'],
        prioritize=True,
        prioritize_top=8,
        generate_payloads=True,
        annotate_code=False,
        deduplicate=False,  # Single profile
        dedupe_threshold=0.7,
        dedupe_strategy='keep_highest_severity',
        top_n=3,
        export_formats=['json', 'html'],
        show_quick_wins=True  # CTF mode shows quick wins
    ),
    
    'security-audit': ScanPreset(
        name='security-audit',
        description='Comprehensive security audit (all files, full analysis)',
        profiles=['owasp', 'code_review'],
        prioritize=False,  # Scan everything
        prioritize_top=0,
        generate_payloads=True,
        annotate_code=True,
        deduplicate=True,
        dedupe_threshold=0.7,
        dedupe_strategy='merge',
        top_n=10,
        export_formats=['json', 'csv', 'html', 'markdown']
    ),
    
    'pentest': ScanPreset(
        name='pentest',
        description='Penetration testing focus (attack chains, payloads, threat model, taint tracking)',
        profiles=['ctf', 'owasp', 'attacker'],
        prioritize=True,
        prioritize_top=20,
        generate_payloads=True,
        annotate_code=True,
        deduplicate=True,
        dedupe_threshold=0.7,
        dedupe_strategy='keep_highest_severity',
        top_n=15,
        export_formats=['json', 'html', 'markdown'],
        threat_model=True,
        show_quick_wins=True,  # Pentest mode shows quick wins
        show_chains=True  # Pentest mode includes taint tracking
    ),
    
    'compliance': ScanPreset(
        name='compliance',
        description='Compliance-focused scan (SOC2, PCI-DSS, regulatory requirements)',
        profiles=['owasp', 'soc2', 'compliance'],
        prioritize=True,
        prioritize_top=25,
        generate_payloads=False,
        annotate_code=True,
        deduplicate=True,
        dedupe_threshold=0.7,
        dedupe_strategy='merge',
        top_n=20,
        export_formats=['json', 'csv', 'html']
    )
}


# ============================================================================
# Smart Defaults System
# ============================================================================

class SmartDefaults:
    """Automatically determine optimal settings based on scan context."""
    
    @staticmethod
    def should_auto_prioritize(num_files: int, threshold: int = 50) -> bool:
        """Auto-enable prioritization for large repositories."""
        return num_files > threshold
    
    @staticmethod
    def should_auto_deduplicate(profiles: List[str]) -> bool:
        """Auto-enable deduplication when using multiple profiles."""
        return len(profiles) > 1
    
    @staticmethod
    def should_auto_parallel(num_files: int, threshold: int = 20) -> bool:
        """Auto-enable parallel processing for larger scans."""
        return num_files > threshold
    
    @staticmethod
    def calculate_smart_top_n(total_findings: int, min_n: int = 3, max_n: int = 15) -> int:
        """Calculate smart top-n based on findings count."""
        if total_findings == 0:
            return 0
        # Return 10-20% of findings, bounded by min/max
        smart_n = max(min_n, min(max_n, total_findings // 5))
        return smart_n
    
    @staticmethod
    def calculate_smart_prioritize_top(num_files: int) -> int:
        """Calculate smart prioritization limit based on file count."""
        if num_files <= 10:
            return num_files  # Analyze all
        elif num_files <= 30:
            return 15
        elif num_files <= 100:
            return 25
        else:
            return 30  # Cap at 30 for very large repos
    
    @staticmethod
    def should_add_html_export(generate_payloads: bool, annotate_code: bool) -> bool:
        """Add HTML export if visual features are enabled."""
        return generate_payloads or annotate_code
    
    @staticmethod
    def apply_smart_defaults(
        args: dict,
        num_files: int,
        profiles: List[str]
    ) -> dict:
        """
        Apply smart defaults to scan arguments.
        
        Args:
            args: Current argument dictionary
            num_files: Number of files to scan
            profiles: List of profiles to use
        
        Returns:
            Updated arguments with smart defaults applied
        """
        enhanced = args.copy()
        
        # Auto-prioritize for large repos
        if not enhanced.get('prioritize') and SmartDefaults.should_auto_prioritize(num_files):
            enhanced['prioritize'] = True
            enhanced['prioritize_top'] = SmartDefaults.calculate_smart_prioritize_top(num_files)
        
        # Auto-deduplicate with multiple profiles
        if not enhanced.get('deduplicate') and SmartDefaults.should_auto_deduplicate(profiles):
            enhanced['deduplicate'] = True
            enhanced['dedupe_threshold'] = 0.7
            enhanced['dedupe_strategy'] = 'keep_highest_severity'
        
        # Auto-parallel for larger scans
        if not enhanced.get('parallel') and SmartDefaults.should_auto_parallel(num_files):
            enhanced['parallel'] = True
        
        # Smart export formats
        exports = set(enhanced.get('export_format', ['json', 'markdown']))
        if SmartDefaults.should_add_html_export(
            enhanced.get('generate_payloads', False),
            enhanced.get('annotate_code', False)
        ):
            exports.add('html')
        enhanced['export_format'] = list(exports)
        
        return enhanced


# ============================================================================
# Tech Stack Detection
# ============================================================================

class TechStackDetector:
    """Detect application frameworks and technologies."""
    
    @staticmethod
    def detect(repo_path: Path) -> Dict[str, any]:
        """
        Detect tech stack and application characteristics.
        
        Returns dict with:
        - frameworks: List of detected frameworks
        - languages: List of primary languages
        - app_type: web_api, web_app, microservice, cli, etc.
        - entry_points: Detected entry points (routes, endpoints)
        """
        frameworks = []
        languages = set()
        app_type = 'unknown'
        
        # Python detection
        requirements_file = repo_path / "requirements.txt"
        if requirements_file.exists():
            languages.add('Python')
            content = requirements_file.read_text().lower()
            if 'flask' in content:
                frameworks.append('Flask')
                app_type = 'web_app'
            if 'django' in content:
                frameworks.append('Django')
                app_type = 'web_app'
            if 'fastapi' in content:
                frameworks.append('FastAPI')
                app_type = 'web_api'
            if 'grpc' in content or 'protobuf' in content:
                frameworks.append('gRPC')
                if not app_type or app_type == 'unknown':
                    app_type = 'microservice'
        
        # Node.js detection
        package_json = repo_path / "package.json"
        if package_json.exists():
            languages.add('JavaScript/TypeScript')
            content = package_json.read_text().lower()
            if 'express' in content:
                frameworks.append('Express')
                app_type = 'web_api'
            if 'react' in content:
                frameworks.append('React')
            if 'vue' in content:
                frameworks.append('Vue')
            if 'angular' in content:
                frameworks.append('Angular')
        
        # Go detection
        go_mod = repo_path / "go.mod"
        if go_mod.exists():
            languages.add('Go')
            content = go_mod.read_text().lower()
            if 'gin' in content or 'echo' in content or 'fiber' in content:
                frameworks.append('Go Web Framework')
                app_type = 'web_api'
        
        # Java detection
        pom_xml = repo_path / "pom.xml"
        if pom_xml.exists():
            languages.add('Java')
            content = pom_xml.read_text().lower()
            if 'spring' in content:
                frameworks.append('Spring Boot')
                app_type = 'web_app'
        
        # PHP detection
        composer_json = repo_path / "composer.json"
        if composer_json.exists():
            languages.add('PHP')
            content = composer_json.read_text().lower()
            if 'laravel' in content:
                frameworks.append('Laravel')
                app_type = 'web_app'
            if 'symfony' in content:
                frameworks.append('Symfony')
                app_type = 'web_app'
        
        # Docker = likely microservice or web app
        if (repo_path / "Dockerfile").exists():
            if not app_type or app_type == 'unknown':
                app_type = 'containerized_app'
        
        return {
            'frameworks': frameworks or ['Unknown'],
            'languages': list(languages) or ['Unknown'],
            'app_type': app_type,
            'has_docker': (repo_path / "Dockerfile").exists(),
            'has_tests': (repo_path / "tests").exists() or (repo_path / "test").exists()
        }


def get_preset(preset_name: str) -> Optional[ScanPreset]:
    """Get a preset configuration by name."""
    return PRESETS.get(preset_name.lower())


def list_presets() -> List[ScanPreset]:
    """List all available presets."""
    return list(PRESETS.values())

