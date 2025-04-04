#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM比较器 - 比较两个SBOM文件的差异
"""

import logging
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
import re
import time
from tqdm import tqdm

from .parser import SBOMData, SPDXPackage

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
class FileChange:
    """文件变更记录"""
    file_name: str
    old_checksums: List[Dict[str, str]] = field(default_factory=list)
    new_checksums: List[Dict[str, str]] = field(default_factory=list)
    has_content_change: bool = False

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
    # 文件变更
    added_files: List[str] = field(default_factory=list)
    removed_files: List[str] = field(default_factory=list)
    file_changes: List[FileChange] = field(default_factory=list)


class SBOMComparator:
    """SBOM比较器类"""
    
    def __init__(self, sbom_a: SBOMData, sbom_b: SBOMData):
        self.sbom_a = sbom_a
        self.sbom_b = sbom_b
        self.logger = logging.getLogger("sbom-compare.comparator")
    
    def compare(self) -> ComparisonResult:
        """比较两个SBOM"""
        start_time = time.time()
        self.logger.info("开始比较SBOM...")
        print("开始SBOM比较分析...")
        
        # 创建结果对象
        result = ComparisonResult(self.sbom_a, self.sbom_b)
        
        # 获取包名集合
        packages_a = set(self.sbom_a.package_map.keys())
        packages_b = set(self.sbom_b.package_map.keys())
        
        # 找出新增、删除和共有的包
        result.added_packages = list(packages_b - packages_a)
        result.removed_packages = list(packages_a - packages_b)
        common_packages = packages_a & packages_b
        
        # 打印步骤信息
        print(f"发现 {len(result.added_packages)} 个新增包, {len(result.removed_packages)} 个移除包")
        print(f"分析 {len(common_packages)} 个共同包的变更...")
        
        # 分析版本变更
        print("正在分析版本变更...")
        progress = tqdm(common_packages, desc="分析版本变更", unit="包")
        for pkg_name in progress:
            pkg_a = self.sbom_a.get_package_by_name(pkg_name)
            pkg_b = self.sbom_b.get_package_by_name(pkg_name)
            
            # 比较版本（处理NOASSERTION和空字符串）
            version_a = pkg_a.version if pkg_a.version else ""
            version_b = pkg_b.version if pkg_b.version else ""
            
            # 规范化版本号进行比较
            normalized_version_a = self._normalize_version(version_a)
            normalized_version_b = self._normalize_version(version_b)
            
            # 只有当规范化后的版本不同时才记录变更
            if normalized_version_a != normalized_version_b:
                is_major, is_minor, is_patch = self._analyze_version_change(normalized_version_a, normalized_version_b)
                
                # 添加到版本变更列表
                version_change = VersionChange(
                    pkg_name, 
                    version_a, 
                    version_b,
                    is_major=is_major,
                    is_minor=is_minor,
                    is_patch=is_patch
                )
                result.version_changes.append(version_change)
        
        # 分析许可证变更
        print("正在分析许可证变更...")
        progress = tqdm(common_packages, desc="分析许可证变更", unit="包")
        for pkg_name in progress:
            pkg_a = self.sbom_a.get_package_by_name(pkg_name)
            pkg_b = self.sbom_b.get_package_by_name(pkg_name)
            
            # 比较许可证（处理NOASSERTION和空字符串）
            license_a = pkg_a.license_concluded if pkg_a.license_concluded else ""
            license_b = pkg_b.license_concluded if pkg_b.license_concluded else ""
            
            # 规范化许可证进行比较
            normalized_license_a = self._normalize_license(license_a)
            normalized_license_b = self._normalize_license(license_b)
            
            # 只有当规范化后的许可证不同时才记录变更
            if normalized_license_a != normalized_license_b:
                # 检查许可证兼容性
                compatibility_issue = self._check_license_compatibility(license_a, license_b)
                
                # 添加到许可证变更列表
                license_change = LicenseChange(
                    pkg_name,
                    license_a,
                    license_b,
                    compatibility_issue
                )
                result.license_changes.append(license_change)
        
        # 分析供应商变更
        print("正在分析供应商变更...")
        progress = tqdm(common_packages, desc="分析供应商变更", unit="包")
        for pkg_name in progress:
            pkg_a = self.sbom_a.get_package_by_name(pkg_name)
            pkg_b = self.sbom_b.get_package_by_name(pkg_name)
            
            # 比较供应商
            supplier_a = pkg_a.supplier if pkg_a.supplier else ""
            supplier_b = pkg_b.supplier if pkg_b.supplier else ""
            
            if supplier_a != supplier_b:
                # 添加到供应商变更列表
                supplier_change = SupplierChange(
                    pkg_name,
                    supplier_a,
                    supplier_b
                )
                result.supplier_changes.append(supplier_change)
        
        # 分析依赖关系变更
        print("正在分析依赖关系变更...")
        progress = tqdm(common_packages, desc="分析依赖关系变更", unit="包")
        for pkg_name in progress:
            # 获取包的依赖
            deps_a = set(self.sbom_a.package_relationships.get(pkg_name, []))
            deps_b = set(self.sbom_b.package_relationships.get(pkg_name, []))
            
            # 比较依赖关系
            if deps_a != deps_b:
                # 添加到依赖关系变更列表
                dependency_change = DependencyChange(
                    pkg_name,
                    list(deps_b - deps_a),  # 新增依赖
                    list(deps_a - deps_b)   # 移除依赖
                )
                result.dependency_changes.append(dependency_change)
        
        # 分析文件变更
        print("正在分析文件变更...")
        # 获取文件名集合
        files_a = set(self.sbom_a.file_map.keys()) if hasattr(self.sbom_a, 'file_map') else set()
        files_b = set(self.sbom_b.file_map.keys()) if hasattr(self.sbom_b, 'file_map') else set()
        
        # 找出新增、删除和共有的文件
        result.added_files = list(files_b - files_a)
        result.removed_files = list(files_a - files_b)
        common_files = files_a & files_b
        
        print(f"发现 {len(result.added_files)} 个新增文件, {len(result.removed_files)} 个移除文件")
        print(f"分析 {len(common_files)} 个共同文件的变更...")
        
        # 分析文件内容变更
        progress = tqdm(common_files, desc="分析文件内容变更", unit="文件")
        for file_name in progress:
            file_a = self.sbom_a.get_file_by_name(file_name)
            file_b = self.sbom_b.get_file_by_name(file_name)
            
            # 比较文件校验和以检测内容变更
            has_content_change = False
            
            # 获取所有校验和算法类型
            algo_a = {chk['algorithm'] for chk in file_a.checksums if 'algorithm' in chk}
            algo_b = {chk['algorithm'] for chk in file_b.checksums if 'algorithm' in chk}
            common_algos = algo_a & algo_b
            
            # 对于每种常见的算法，比较校验和值
            for algo in common_algos:
                checksum_a = next((chk['checksumValue'] for chk in file_a.checksums 
                                 if chk.get('algorithm') == algo), None)
                checksum_b = next((chk['checksumValue'] for chk in file_b.checksums 
                                 if chk.get('algorithm') == algo), None)
                
                if checksum_a and checksum_b and checksum_a != checksum_b:
                    has_content_change = True
                    break
            
            # 如果校验和有变更或算法集不同，记为内容变更
            if has_content_change or algo_a != algo_b:
                file_change = FileChange(
                    file_name=file_name,
                    old_checksums=file_a.checksums,
                    new_checksums=file_b.checksums,
                    has_content_change=True
                )
                result.file_changes.append(file_change)
                
        # 统计变更总数
        total_changes = (
            len(result.added_packages) + 
            len(result.removed_packages) + 
            len(result.version_changes) + 
            len(result.license_changes) + 
            len(result.supplier_changes) + 
            len(result.dependency_changes) +
            len(result.added_files) + 
            len(result.removed_files) + 
            len(result.file_changes)
        )
        
        end_time = time.time()
        elapsed = end_time - start_time
        self.logger.info(f"SBOM比较完成，找到 {total_changes} 个变更，耗时 {elapsed:.2f} 秒")
        print(f"SBOM比较分析完成，共发现 {total_changes} 个变更，耗时 {elapsed:.2f} 秒")
        return result
    
    def _normalize_version(self, version: str) -> str:
        """规范化版本字符串，移除空格、前缀'v'和版本表达式前缀"""
        if not version or version == "NOASSERTION":
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
    
    def _normalize_license(self, license_text: str) -> str:
        """规范化许可证字符串，处理NOASSERTION等特殊情况"""
        if not license_text or license_text == "NOASSERTION":
            return ""
        return license_text.strip()
    
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
    
    def _check_license_compatibility(self, license_a: str, license_b: str) -> bool:
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