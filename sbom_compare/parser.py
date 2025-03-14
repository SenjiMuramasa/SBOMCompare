#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM解析器 - 解析SPDX-2.3格式的SBOM文件
"""

import os
import logging
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field

logger = logging.getLogger("sbom-compare.parser")

@dataclass
class SPDXPackage:
    """SPDX包信息"""
    name: str
    SPDXID: str
    version: Optional[str] = None
    supplier: Optional[str] = None
    license_concluded: Optional[str] = None
    license_declared: Optional[str] = None
    download_location: Optional[str] = None
    copyright_text: Optional[str] = None
    description: Optional[str] = None
    external_references: List[Dict[str, str]] = field(default_factory=list)

@dataclass
class SPDXRelationship:
    """SPDX关系信息"""
    spdx_element_id: str
    related_spdx_element_id: str
    relationship_type: str

@dataclass
class SPDXDocument:
    """SPDX文档"""
    name: str
    packages: List[SPDXPackage] = field(default_factory=list)
    relationships: List[SPDXRelationship] = field(default_factory=list)
    creation_info: Dict[str, Any] = field(default_factory=dict)

class SBOMData:
    """SBOM数据存储类"""
    
    def __init__(self, document: SPDXDocument, file_path: str):
        self.document = document
        self.file_path = file_path
        self.name = document.name
        self.packages = document.packages
        self.creation_info = document.creation_info
        self.package_relationships = self._extract_relationships()
        self.external_references = self._extract_external_refs()
        self.package_map = {pkg.name: pkg for pkg in self.packages if pkg.name}
        
        # 提取关键信息映射
        self.license_map = {pkg.name: pkg.license_concluded 
                          for pkg in self.packages 
                          if pkg.name and pkg.license_concluded}
        
        self.version_map = {pkg.name: pkg.version 
                          for pkg in self.packages 
                          if pkg.name and pkg.version}
        
        self.supplier_map = {pkg.name: pkg.supplier 
                           for pkg in self.packages 
                           if pkg.name and pkg.supplier}
    
    def _extract_relationships(self) -> Dict[str, List[str]]:
        """提取包之间的依赖关系"""
        relationships = {}
        
        for relationship in self.document.relationships:
            if relationship.relationship_type:
                # 仅处理DEPENDS_ON类型的关系
                if "DEPENDS_ON" in relationship.relationship_type:
                    if relationship.spdx_element_id not in relationships:
                        relationships[relationship.spdx_element_id] = []
                    
                    relationships[relationship.spdx_element_id].append(
                        relationship.related_spdx_element_id
                    )
        
        return relationships
    
    def _extract_external_refs(self) -> Dict[str, Dict[str, str]]:
        """提取外部引用，如CPE、PURL等"""
        external_refs = {}
        
        for pkg in self.packages:
            if pkg.name and hasattr(pkg, 'external_references') and pkg.external_references:
                pkg_refs = {}
                for ref in pkg.external_references:
                    if 'type' in ref and 'locator' in ref:
                        ref_type = ref['type']
                        pkg_refs[ref_type] = ref['locator']
                
                if pkg_refs:
                    external_refs[pkg.name] = pkg_refs
        
        return external_refs
    
    def get_package_by_name(self, name: str) -> Optional[Any]:
        """根据名称获取包"""
        return self.package_map.get(name)
    
    def get_dependencies(self, package_name: str) -> List[str]:
        """获取指定包的依赖项"""
        return self.package_relationships.get(package_name, [])


class SBOMParser:
    """SPDX-2.3格式SBOM文件解析器"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
    
    def parse(self) -> SBOMData:
        """解析SBOM文件并返回数据对象"""
        file_extension = Path(self.file_path).suffix.lower()
        
        try:
            if file_extension in [".json", ".spdx.json"]:
                document = self._parse_json()
            else:
                # 目前只支持JSON格式
                logger.warning(f"不支持的文件格式: {file_extension}，尝试作为JSON解析")
                document = self._parse_json()
            
            return SBOMData(document, self.file_path)
        
        except Exception as e:
            logger.error(f"解析SBOM文件失败: {e}", exc_info=True)
            raise ValueError(f"解析文件 {self.file_path} 失败: {str(e)}")
    
    def _parse_json(self) -> SPDXDocument:
        """解析JSON格式的SPDX文件"""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 创建SPDX文档
        document_name = data.get("name", os.path.basename(self.file_path))
        document = SPDXDocument(name=document_name)
        document.creation_info = data.get("creationInfo", {})
        
        # 解析包信息
        packages = []
        for pkg_data in data.get("packages", []):
            package = SPDXPackage(
                name=pkg_data.get("name", ""),
                SPDXID=pkg_data.get("SPDXID", ""),
                version=pkg_data.get("versionInfo"),
                supplier=pkg_data.get("supplier"),
                license_concluded=pkg_data.get("licenseConcluded"),
                license_declared=pkg_data.get("licenseDeclared"),
                download_location=pkg_data.get("downloadLocation"),
                copyright_text=pkg_data.get("copyrightText"),
                description=pkg_data.get("description")
            )
            
            # 解析外部引用
            external_refs = pkg_data.get("externalRefs", [])
            if external_refs:
                package.external_references = []
                for ref in external_refs:
                    package.external_references.append({
                        "type": ref.get("referenceType", ""),
                        "locator": ref.get("referenceLocator", "")
                    })
            
            packages.append(package)
        
        document.packages = packages
        
        # 解析关系信息
        relationships = []
        for rel_data in data.get("relationships", []):
            relationship = SPDXRelationship(
                spdx_element_id=rel_data.get("spdxElementId", ""),
                related_spdx_element_id=rel_data.get("relatedSpdxElement", ""),
                relationship_type=rel_data.get("relationshipType", "")
            )
            relationships.append(relationship)
        
        document.relationships = relationships
        
        return document 