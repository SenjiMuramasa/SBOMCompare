#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM比较器 - 比较两个SBOM文件的差异
"""

import logging
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field

from .parser import SBOMData

logger = logging.getLogger("sbom-compare.comparator")

@dataclass
class VersionChange:
    """版本变更记录"""
    package_name: str
    old_version: str
    new_version: str
    is_major: bool = False
    is_minor: bool = False
    is_patch: bool = False

@dataclass
class LicenseChange:
    """许可证变更记录"""
    package_name: str
    old_license: str
    new_license: str
    compatibility_issue: bool = False

@dataclass
class SupplierChange:
    """供应商变更记录"""
    package_name: str
    old_supplier: str
    new_supplier: str

@dataclass
class DependencyChange:
    """依赖关系变更记录"""
    package_name: str
    added_dependencies: List[str] = field(default_factory=list)
    removed_dependencies: List[str] = field(default_factory=list)

@dataclass
class ComparisonResult:
    """SBOM比较结果"""
    sbom_a: SBOMData
    sbom_b: SBOMData
    added_packages: List[str] = field(default_factory=list)
    removed_packages: List[str] = field(default_factory=list)
    version_changes: List[VersionChange] = field(default_factory=list)
    license_changes: List[LicenseChange] = field(default_factory=list)
    supplier_changes: List[SupplierChange] = field(default_factory=list)
    dependency_changes: List[DependencyChange] = field(default_factory=list)


class SBOMComparator:
    """SBOM比较器类"""
    
    def __init__(self, sbom_a: SBOMData, sbom_b: SBOMData):
        self.sbom_a = sbom_a
        self.sbom_b = sbom_b
        self.result = ComparisonResult(sbom_a, sbom_b)
    
    def compare(self) -> ComparisonResult:
        """比较两个SBOM并返回差异结果"""
        logger.info("开始比较SBOM文件")
        
        # 比较包集合
        self._compare_package_sets()
        
        # 比较相同包的版本变化
        self._compare_versions()
        
        # 比较许可证变化
        self._compare_licenses()
        
        # 比较供应商变化
        self._compare_suppliers()
        
        # 比较依赖关系变化
        self._compare_dependencies()
        
        logger.info(f"比较完成，共发现 {self._count_changes()} 处变化")
        return self.result
    
    def _count_changes(self) -> int:
        """计算总的变化数量"""
        return (
            len(self.result.added_packages) +
            len(self.result.removed_packages) +
            len(self.result.version_changes) +
            len(self.result.license_changes) +
            len(self.result.supplier_changes) +
            len(self.result.dependency_changes)
        )
    
    def _compare_package_sets(self) -> None:
        """比较两个SBOM中的包集合"""
        packages_a = set(self.sbom_a.package_map.keys())
        packages_b = set(self.sbom_b.package_map.keys())
        
        added_packages = packages_b - packages_a
        removed_packages = packages_a - packages_b
        
        self.result.added_packages = sorted(list(added_packages))
        self.result.removed_packages = sorted(list(removed_packages))
        
        logger.debug(f"发现 {len(added_packages)} 个新增包，{len(removed_packages)} 个移除包")
    
    def _compare_versions(self) -> None:
        """比较相同包的版本变化"""
        common_packages = set(self.sbom_a.package_map.keys()) & set(self.sbom_b.package_map.keys())
        
        for pkg_name in common_packages:
            version_a = self.sbom_a.version_map.get(pkg_name)
            version_b = self.sbom_b.version_map.get(pkg_name)
            
            if version_a and version_b:
                # 规范化版本号，去掉前缀"v"并移除空格
                normalized_version_a = self._normalize_version(version_a)
                normalized_version_b = self._normalize_version(version_b)
                
                # 只有当规范化后的版本号不同时才记录变更
                if normalized_version_a != normalized_version_b:
                    # 检测是主版本、次版本还是补丁版本变更
                    is_major, is_minor, is_patch = self._analyze_version_change(normalized_version_a, normalized_version_b)
                    
                    change = VersionChange(
                        package_name=pkg_name,
                        old_version=version_a,
                        new_version=version_b,
                        is_major=is_major,
                        is_minor=is_minor,
                        is_patch=is_patch
                    )
                    self.result.version_changes.append(change)
        
        logger.debug(f"发现 {len(self.result.version_changes)} 个版本变更")
    
    def _normalize_version(self, version: str) -> str:
        """规范化版本字符串，移除空格、前缀'v'和版本表达式前缀"""
        if not version:
            return ""
            
        # 标准化版本前缀符号周围的空格，如">= 1.0.0" 变为 ">=1.0.0"
        for op in [">=", "<=", ">", "<", "==", "~=", "!="]:
            if op in version:
                # 去除操作符周围的空格
                version = version.replace(f"{op} ", op).replace(f" {op}", op)
        
        # 移除版本号中的所有空格
        version = version.replace(" ", "")
        
        # 去除版本表达式前缀（如 "==1.8.0" -> "1.8.0"）
        for op in [">=", "<=", ">", "<", "==", "~=", "!="]:
            if version.startswith(op):
                version = version[len(op):]
                break
        
        # 去除前缀"v"
        if version.startswith('v'):
            version = version[1:]
            
        return version
    
    def _analyze_version_change(self, version_a: str, version_b: str) -> Tuple[bool, bool, bool]:
        """分析版本变更的类型 (主版本、次版本、补丁版本)"""
        try:
            # 尝试解析语义化版本
            parts_a = version_a.split('.')
            parts_b = version_b.split('.')
            
            if len(parts_a) >= 1 and len(parts_b) >= 1:
                major_a = int(parts_a[0].split('-')[0])  # 处理类似 "1-alpha" 的情况
                major_b = int(parts_b[0].split('-')[0])
                
                if major_a != major_b:
                    return True, False, False  # 主版本变更
            
            if len(parts_a) >= 2 and len(parts_b) >= 2:
                minor_a = int(parts_a[1].split('-')[0])
                minor_b = int(parts_b[1].split('-')[0])
                
                if minor_a != minor_b:
                    return False, True, False  # 次版本变更
            
            if len(parts_a) >= 3 and len(parts_b) >= 3:
                patch_a = int(parts_a[2].split('-')[0])
                patch_b = int(parts_b[2].split('-')[0])
                
                if patch_a != patch_b:
                    return False, False, True  # 补丁版本变更
        
        except (ValueError, IndexError):
            # 无法解析为语义化版本，视为一般变更
            pass
        
        # 默认为一般版本变更
        return False, False, False
    
    def _compare_licenses(self) -> None:
        """比较许可证变化"""
        common_packages = set(self.sbom_a.package_map.keys()) & set(self.sbom_b.package_map.keys())
        
        for pkg_name in common_packages:
            license_a = self.sbom_a.license_map.get(pkg_name)
            license_b = self.sbom_b.license_map.get(pkg_name)
            
            if license_a and license_b and license_a != license_b:
                # 检测许可证兼容性问题
                compatibility_issue = self._detect_license_compatibility_issue(license_a, license_b)
                
                change = LicenseChange(
                    package_name=pkg_name,
                    old_license=license_a,
                    new_license=license_b,
                    compatibility_issue=compatibility_issue
                )
                self.result.license_changes.append(change)
        
        logger.debug(f"发现 {len(self.result.license_changes)} 个许可证变更")
    
    def _detect_license_compatibility_issue(self, license_a: str, license_b: str) -> bool:
        """检测许可证变更是否存在兼容性问题"""
        # 定义常见的许可证兼容性问题组合
        incompatible_pairs = [
            # GPL系列与专有/商业许可证不兼容
            ("GPL", "Proprietary"),
            ("GPL", "Commercial"),
            # AGPL与商业/专有许可证不兼容
            ("AGPL", "Proprietary"),
            ("AGPL", "Commercial"),
            # GPL与Apache的兼容性问题
            ("GPL-2.0", "Apache-2.0"),
        ]
        
        # 检查是否存在于不兼容许可证列表中
        for pair in incompatible_pairs:
            if (pair[0] in license_a and pair[1] in license_b) or (pair[0] in license_b and pair[1] in license_a):
                return True
        
        # 从宽松到严格的许可证变更通常不会产生问题
        # 从严格到宽松的许可证变更可能导致问题
        permissive_to_copyleft = [
            ("MIT", "GPL"),
            ("BSD", "GPL"),
            ("Apache", "GPL"),
            ("ISC", "GPL"),
        ]
        
        for pair in permissive_to_copyleft:
            if pair[0] in license_a and pair[1] in license_b:
                return False  # 从宽松到严格
            if pair[0] in license_b and pair[1] in license_a:
                return True   # 从严格到宽松
        
        return False
    
    def _compare_suppliers(self) -> None:
        """比较供应商变化"""
        common_packages = set(self.sbom_a.package_map.keys()) & set(self.sbom_b.package_map.keys())
        
        for pkg_name in common_packages:
            supplier_a = self.sbom_a.supplier_map.get(pkg_name)
            supplier_b = self.sbom_b.supplier_map.get(pkg_name)
            
            if supplier_a and supplier_b and supplier_a != supplier_b:
                change = SupplierChange(
                    package_name=pkg_name,
                    old_supplier=supplier_a,
                    new_supplier=supplier_b
                )
                self.result.supplier_changes.append(change)
        
        logger.debug(f"发现 {len(self.result.supplier_changes)} 个供应商变更")
    
    def _compare_dependencies(self) -> None:
        """比较依赖关系变化"""
        common_packages = set(self.sbom_a.package_map.keys()) & set(self.sbom_b.package_map.keys())
        
        for pkg_name in common_packages:
            deps_a = set(self.sbom_a.get_dependencies(pkg_name))
            deps_b = set(self.sbom_b.get_dependencies(pkg_name))
            
            added_deps = deps_b - deps_a
            removed_deps = deps_a - deps_b
            
            if added_deps or removed_deps:
                change = DependencyChange(
                    package_name=pkg_name,
                    added_dependencies=sorted(list(added_deps)),
                    removed_dependencies=sorted(list(removed_deps))
                )
                self.result.dependency_changes.append(change)
        
        logger.debug(f"发现 {len(self.result.dependency_changes)} 个依赖关系变更") 