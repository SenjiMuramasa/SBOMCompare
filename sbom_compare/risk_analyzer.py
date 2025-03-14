#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM风险分析器 - 分析SBOM差异所暗示的潜在供应链风险
"""

import logging
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field

from .comparator import ComparisonResult, VersionChange, LicenseChange, SupplierChange

logger = logging.getLogger("sbom-compare.risk-analyzer")

@dataclass
class Risk:
    """风险记录"""
    level: str  # high, medium, low
    category: str  # 风险类别
    description: str  # 风险描述
    affected_packages: List[str]  # 受影响的包
    recommendation: str  # 建议的缓解措施
    supply_chain_stage: Optional[str] = None  # 供应链阶段：source, ci, container


class RiskAnalyzer:
    """SBOM差异风险分析器"""
    
    def __init__(self, comparison_result: ComparisonResult, source_type: str = "generic"):
        """
        初始化风险分析器
        
        Args:
            comparison_result: SBOM比较结果
            source_type: 比较的SBOM类型，可选值:
                - "source_to_ci": 源代码SBOM与CI中生成的SBOM比较
                - "ci_to_container": CI中生成的SBOM与容器SBOM比较
                - "source_to_container": 源代码SBOM与容器SBOM比较
                - "generic": 通用SBOM比较（默认）
        """
        self.comparison = comparison_result
        self.source_type = source_type
        self.risks: Dict[str, List[Risk]] = {
            "high": [],
            "medium": [],
            "low": []
        }
    
    def analyze(self) -> Dict[str, List[Risk]]:
        """分析比较结果中的风险"""
        logger.info(f"开始风险分析，比较类型: {self.source_type}")
        
        # 基本风险分析
        self._analyze_added_packages()
        self._analyze_removed_packages()
        self._analyze_version_changes()
        self._analyze_license_changes()
        self._analyze_supplier_changes()
        self._analyze_dependency_changes()
        
        # 根据SBOM比较类型进行特定的风险分析
        if self.source_type != "generic":
            self._analyze_supply_chain_risks()
        
        # 打印风险摘要
        total_risks = sum(len(risks) for risks in self.risks.values())
        logger.info(f"风险分析完成，共识别出 {total_risks} 个风险")
        
        return self.risks
    
    def _analyze_added_packages(self) -> None:
        """分析新增包的风险"""
        added_packages = self.comparison.added_packages
        
        if not added_packages:
            return
        
        # 风险：大量新增包
        if len(added_packages) > 10:
            self.risks["medium"].append(Risk(
                level="medium",
                category="依赖扩张",
                description=f"新增了大量包（{len(added_packages)}个），可能增加软件供应链的复杂性和攻击面",
                affected_packages=added_packages,
                recommendation="审查新增包的必要性，尤其是那些不直接支持核心功能的包"
            ))
        
        # 风险：缺少许可证信息的新增包
        missing_license_packages = []
        for pkg_name in added_packages:
            pkg = self.comparison.sbom_b.get_package_by_name(pkg_name)
            if pkg and not pkg.license_concluded:
                missing_license_packages.append(pkg_name)
        
        if missing_license_packages:
            self.risks["medium"].append(Risk(
                level="medium",
                category="许可证合规",
                description=f"{len(missing_license_packages)}个新增包缺少明确的许可证信息",
                affected_packages=missing_license_packages,
                recommendation="确保所有新增包都有明确的许可证信息，以避免潜在的法律风险"
            ))
        
        # 风险：缺少供应商信息的新增包
        missing_supplier_packages = []
        for pkg_name in added_packages:
            pkg = self.comparison.sbom_b.get_package_by_name(pkg_name)
            if pkg and not pkg.supplier:
                missing_supplier_packages.append(pkg_name)
        
        if missing_supplier_packages:
            self.risks["low"].append(Risk(
                level="low",
                category="供应链透明度",
                description=f"{len(missing_supplier_packages)}个新增包缺少供应商信息",
                affected_packages=missing_supplier_packages,
                recommendation="完善包的供应商信息，提高供应链透明度"
            ))
    
    def _analyze_removed_packages(self) -> None:
        """分析移除包的风险"""
        removed_packages = self.comparison.removed_packages
        
        if not removed_packages:
            return
        
        # 风险：大量移除包
        if len(removed_packages) > 10:
            self.risks["medium"].append(Risk(
                level="medium",
                category="依赖变更",
                description=f"移除了大量包（{len(removed_packages)}个），可能表明软件架构发生了重大变更",
                affected_packages=removed_packages,
                recommendation="确认所有被移除的依赖项功能都已经被适当替代或不再需要"
            ))
        
        # 风险：移除关键包
        # 这里需要预定义关键包列表或使用启发式方法
        critical_packages = []  # 替换为实际的关键包检测逻辑
        
        if critical_packages:
            self.risks["high"].append(Risk(
                level="high",
                category="关键组件变更",
                description=f"移除了{len(critical_packages)}个关键包，可能影响核心功能",
                affected_packages=critical_packages,
                recommendation="验证关键功能是否受到影响，并确认是否有适当的替代方案"
            ))
    
    def _analyze_version_changes(self) -> None:
        """分析版本变更的风险"""
        version_changes = self.comparison.version_changes
        
        if not version_changes:
            return
        
        # 风险：主版本变更
        major_changes = [change for change in version_changes if change.is_major]
        if major_changes:
            affected_packages = [change.package_name for change in major_changes]
            self.risks["medium"].append(Risk(
                level="medium",
                category="重大版本变更",
                description=f"{len(major_changes)}个包进行了主版本升级，可能包含不兼容的API变更",
                affected_packages=affected_packages,
                recommendation="审查主版本变更的包的变更日志，确认API兼容性，并进行全面测试"
            ))
        
        # 风险：版本降级
        downgrade_changes = []
        for change in version_changes:
            try:
                old_parts = [int(p.split('-')[0]) for p in change.old_version.split('.')]
                new_parts = [int(p.split('-')[0]) for p in change.new_version.split('.')]
                
                # 简单比较版本号
                for i in range(min(len(old_parts), len(new_parts))):
                    if new_parts[i] < old_parts[i]:
                        downgrade_changes.append(change)
                        break
                    elif new_parts[i] > old_parts[i]:
                        break
            except (ValueError, IndexError):
                # 无法比较版本号，跳过
                continue
        
        if downgrade_changes:
            affected_packages = [change.package_name for change in downgrade_changes]
            self.risks["high"].append(Risk(
                level="high",
                category="版本降级",
                description=f"{len(downgrade_changes)}个包的版本被降级，可能丢失安全修复或功能",
                affected_packages=affected_packages,
                recommendation="调查版本降级的原因，确认是否有意为之，以及是否丢失了重要的安全修复"
            ))
    
    def _analyze_license_changes(self) -> None:
        """分析许可证变更的风险"""
        license_changes = self.comparison.license_changes
        
        if not license_changes:
            return
        
        # 风险：许可证兼容性问题
        incompatible_changes = [change for change in license_changes if change.compatibility_issue]
        if incompatible_changes:
            affected_packages = [change.package_name for change in incompatible_changes]
            self.risks["high"].append(Risk(
                level="high",
                category="许可证兼容性",
                description=f"{len(incompatible_changes)}个包的许可证变更可能导致法律兼容性问题",
                affected_packages=affected_packages,
                recommendation="咨询法律顾问评估许可证变更的合规性风险"
            ))
        
        # 风险：从开源到商业/专有许可证
        opensrc_to_commercial = []
        for change in license_changes:
            if (change.old_license and change.new_license and 
                any(oss in change.old_license.upper() for oss in ["MIT", "BSD", "APACHE", "GPL"]) and 
                any(comm in change.new_license.upper() for comm in ["PROPRIETARY", "COMMERCIAL"])):
                opensrc_to_commercial.append(change)
        
        if opensrc_to_commercial:
            affected_packages = [change.package_name for change in opensrc_to_commercial]
            self.risks["medium"].append(Risk(
                level="medium",
                category="许可证商业化",
                description=f"{len(opensrc_to_commercial)}个包从开源许可证变更为商业/专有许可证",
                affected_packages=affected_packages,
                recommendation="评估许可证变更对项目的财务和法律影响"
            ))
    
    def _analyze_supplier_changes(self) -> None:
        """分析供应商变更的风险"""
        supplier_changes = self.comparison.supplier_changes
        
        if not supplier_changes:
            return
        
        # 风险：供应商变更可能表明供应链重定向
        if supplier_changes:
            affected_packages = [change.package_name for change in supplier_changes]
            self.risks["medium"].append(Risk(
                level="medium",
                category="供应链变更",
                description=f"{len(supplier_changes)}个包变更了供应商，可能表明供应链被重定向",
                affected_packages=affected_packages,
                recommendation="验证新供应商的可信度，并确认变更是有意的而非供应链攻击"
            ))
    
    def _analyze_dependency_changes(self) -> None:
        """分析依赖关系变更的风险"""
        dependency_changes = self.comparison.dependency_changes
        
        if not dependency_changes:
            return
        
        # 风险：增加了过多的间接依赖
        high_added_deps = []
        for change in dependency_changes:
            if len(change.added_dependencies) > 5:
                high_added_deps.append(change.package_name)
        
        if high_added_deps:
            self.risks["low"].append(Risk(
                level="low",
                category="依赖复杂性",
                description=f"{len(high_added_deps)}个包新增了大量的间接依赖，增加了供应链复杂性",
                affected_packages=high_added_deps,
                recommendation="审查这些包是否真的需要这么多依赖，考虑简化依赖关系"
            ))
    
    def _analyze_supply_chain_risks(self) -> None:
        """分析软件供应链特定阶段的风险"""
        if self.source_type == "source_to_ci":
            self._analyze_source_to_ci_risks()
        elif self.source_type == "ci_to_container":
            self._analyze_ci_to_container_risks()
        elif self.source_type == "source_to_container":
            self._analyze_source_to_container_risks()
    
    def _analyze_source_to_ci_risks(self) -> None:
        """分析源代码到CI阶段的风险"""
        # 检测CI阶段新增的包
        added_packages = self.comparison.added_packages
        if added_packages:
            self.risks["high"].append(Risk(
                level="high",
                category="CI阶段新增包",
                description=f"在CI阶段新增了{len(added_packages)}个包，这些包在源代码中未定义",
                affected_packages=added_packages,
                recommendation="审核CI配置，确保所有依赖都在源代码中明确定义，避免CI过程中引入未授权的包",
                supply_chain_stage="ci"
            ))
        
        # 检测CI阶段版本变更
        unexpected_version_changes = []
        for change in self.comparison.version_changes:
            # 可以根据项目特定规则定义"预期"和"非预期"的版本变更
            unexpected_version_changes.append(change.package_name)
        
        if unexpected_version_changes:
            self.risks["medium"].append(Risk(
                level="medium",
                category="CI阶段版本变更",
                description=f"在CI阶段，{len(unexpected_version_changes)}个包的版本发生了变更",
                affected_packages=unexpected_version_changes,
                recommendation="检查CI配置，确保依赖版本锁定，防止自动更新引入未测试的版本",
                supply_chain_stage="ci"
            ))
    
    def _analyze_ci_to_container_risks(self) -> None:
        """分析CI到容器阶段的风险"""
        # 检测容器中新增的包（可能是基础镜像引入的）
        added_packages = self.comparison.added_packages
        if added_packages:
            self.risks["medium"].append(Risk(
                level="medium",
                category="容器镜像额外包",
                description=f"容器镜像中包含{len(added_packages)}个在CI构建中未出现的包",
                affected_packages=added_packages,
                recommendation="审核容器基础镜像，确保不包含多余或潜在危险的包",
                supply_chain_stage="container"
            ))
        
        # 检测容器中缺失的包（可能是构建问题）
        removed_packages = self.comparison.removed_packages
        if removed_packages:
            self.risks["high"].append(Risk(
                level="high",
                category="容器缺失包",
                description=f"容器镜像中缺少{len(removed_packages)}个在CI构建中存在的包",
                affected_packages=removed_packages,
                recommendation="检查容器构建过程，确保所有必要的依赖都被正确打包",
                supply_chain_stage="container"
            ))
    
    def _analyze_source_to_container_risks(self) -> None:
        """分析源代码到容器阶段的风险（端到端）"""
        # 源代码到容器的完整性分析
        # 这可能包括前两个阶段的组合风险，以及一些特定的端到端风险
        
        # 检测端到端过程中的包版本变更
        version_changes = self.comparison.version_changes
        if version_changes:
            critical_changes = [change.package_name for change in version_changes if change.is_major]
            if critical_changes:
                self.risks["high"].append(Risk(
                    level="high",
                    category="端到端版本漂移",
                    description=f"从源代码到容器，{len(critical_changes)}个包发生了主版本变更",
                    affected_packages=critical_changes,
                    recommendation="实施严格的版本锁定策略，确保从源代码到容器的整个过程中版本一致",
                    supply_chain_stage="end-to-end"
                ))
        
        # 检测未声明的容器依赖
        added_packages = self.comparison.added_packages
        if added_packages:
            suspicious_packages = []
            for pkg_name in added_packages:
                # 这里可以添加检测可疑包的逻辑
                # 例如，检查是否来自不受信任的源，或者是否有已知的漏洞
                suspicious_packages.append(pkg_name)
            
            if suspicious_packages:
                self.risks["high"].append(Risk(
                    level="high",
                    category="容器供应链污染",
                    description=f"容器中存在{len(suspicious_packages)}个在源代码中未声明的可疑包",
                    affected_packages=suspicious_packages,
                    recommendation="审核完整软件供应链，确保所有包都经过审查和授权",
                    supply_chain_stage="end-to-end"
                ))
        
        # 检测供应商变更
        if self.comparison.supplier_changes:
            self.risks["high"].append(Risk(
                level="high",
                category="供应商变更",
                description=f"从源代码到容器，{len(self.comparison.supplier_changes)}个包的供应商发生了变更",
                affected_packages=[change.package_name for change in self.comparison.supplier_changes],
                recommendation="调查供应商变更的原因，确认不是供应链攻击的结果",
                supply_chain_stage="end-to-end"
            )) 