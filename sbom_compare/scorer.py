#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM安全评分器 - 评估软件供应链安全性
"""

import logging
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .comparator import ComparisonResult
from .scorecard import ScorecardAPI

logger = logging.getLogger("sbom-compare.scorer")

@dataclass
class ScoreCategory:
    """评分类别"""
    name: str  # 类别名称
    score: float  # 得分
    max_score: float  # 最高分
    details: List[str]  # 详细信息
    impact_factors: List[str]  # 影响因素


@dataclass
class SecurityScore:
    """安全评分"""
    total_score: float  # 总分
    max_score: float  # 最高分
    grade: str  # 等级
    categories: Dict[str, ScoreCategory]  # 各类别得分
    source_type: str  # SBOM比较类型
    summary: str  # 总结


class SecurityScoreCalculator:
    """安全评分计算器"""
    
    def __init__(self, comparison_result: ComparisonResult, source_type: str = "generic",
                 github_org: Optional[str] = None, github_repo: Optional[str] = None):
        """
        初始化评分计算器
        
        Args:
            comparison_result: SBOM比较结果
            source_type: 比较的SBOM类型，可选值:
                - "source_to_ci": 源代码SBOM与CI中生成的SBOM比较
                - "ci_to_container": CI中生成的SBOM与容器SBOM比较
                - "source_to_container": 源代码SBOM与容器SBOM比较
                - "generic": 通用SBOM比较（默认）
            github_org: GitHub组织名称（用于获取Scorecard评分）
            github_repo: GitHub仓库名称（用于获取Scorecard评分）
        """
        self.result = comparison_result
        self.source_type = source_type
        self.has_risks = hasattr(comparison_result, "risks")
        self.github_org = github_org
        self.github_repo = github_repo
        self.scorecard_api = ScorecardAPI()
        self.scorecard_score = None
        self.scorecard_details = None
        
        # 定义各类别的最高分（满分10分）
        self.max_scores = {
            "dependency_integrity": 2.0,    # 依赖完整性
            "version_consistency": 1.5,     # 版本一致性
            "license_compliance": 1.5,      # 许可证合规性
            "supply_chain_integrity": 2.0,  # 供应链完整性
            "risk_assessment": 1.0,         # 风险评估
            "scorecard_assessment": 2.0     # Scorecard评估
        }
        
        # 调整不同阶段的评分权重
        self._adjust_weights_by_source_type()
        
        # 如果提供了GitHub信息，获取Scorecard评分
        if github_org and github_repo:
            self.scorecard_score, self.scorecard_details = self.scorecard_api.get_project_score(github_org, github_repo)
    
    def _adjust_weights_by_source_type(self) -> None:
        """根据比较类型调整权重"""
        if self.source_type == "source_to_ci":
            # CI阶段更关注依赖完整性和版本一致性
            self.max_scores["dependency_integrity"] = 3.0
            self.max_scores["version_consistency"] = 2.5
            self.max_scores["supply_chain_integrity"] = 1.5
        elif self.source_type == "ci_to_container":
            # 容器阶段更关注供应链完整性
            self.max_scores["dependency_integrity"] = 2.0
            self.max_scores["supply_chain_integrity"] = 3.0
        elif self.source_type == "source_to_container":
            # 端到端更均衡但强调供应链完整性
            self.max_scores["supply_chain_integrity"] = 3.0
            self.max_scores["risk_assessment"] = 2.0
            self.max_scores["dependency_integrity"] = 2.0
        
        # 确保总分为10
        total = sum(self.max_scores.values())
        if total != 10.0:
            factor = 10.0 / total
            self.max_scores = {k: v * factor for k, v in self.max_scores.items()}
    
    def calculate(self) -> SecurityScore:
        """计算安全评分"""
        logger.info("开始计算软件供应链安全评分")
        
        # 计算各类别得分
        dependency_integrity = self._score_dependency_integrity()
        version_consistency = self._score_version_consistency()
        license_compliance = self._score_license_compliance()
        supply_chain_integrity = self._score_supply_chain_integrity()
        risk_assessment = self._score_risk_assessment()
        scorecard_assessment = self._score_scorecard_assessment()
        
        # 汇总类别得分
        categories = {
            "dependency_integrity": dependency_integrity,
            "version_consistency": version_consistency,
            "license_compliance": license_compliance,
            "supply_chain_integrity": supply_chain_integrity,
            "risk_assessment": risk_assessment,
            "scorecard_assessment": scorecard_assessment
        }
        
        # 计算总分
        total_score = sum(cat.score for cat in categories.values())
        max_score = sum(cat.max_score for cat in categories.values())
        
        # 计算等级
        grade = self._calculate_grade(total_score, max_score)
        
        # 生成总结
        summary = self._generate_summary(total_score, max_score, grade, categories)
        
        # 创建评分结果
        score = SecurityScore(
            total_score=total_score,
            max_score=max_score,
            grade=grade,
            categories=categories,
            source_type=self.source_type,
            summary=summary
        )
        
        logger.info(f"安全评分计算完成：{total_score:.1f}/{max_score:.1f} ({grade})")
        return score
    
    def _score_dependency_integrity(self) -> ScoreCategory:
        """评估依赖完整性"""
        max_score = self.max_scores["dependency_integrity"]
        score = max_score
        details = []
        impact_factors = []
        
        # 计算基线包数量 (用于相对变化计算)
        baseline_count = len(self.result.sbom_a.packages)
        if baseline_count == 0:
            baseline_count = 1  # 避免除零错误
        
        # 评估新增包
        added_packages = self.result.added_packages
        if added_packages:
            added_ratio = len(added_packages) / baseline_count
            penalty = min(max_score * 0.4, max_score * 0.1 * added_ratio * 10)
            score -= penalty
            
            if len(added_packages) > 10:
                details.append(f"大量新增包({len(added_packages)}个)可能增加攻击面")
                impact_factors.append("大量新增依赖")
            elif len(added_packages) > 0:
                details.append(f"新增了{len(added_packages)}个包")
        
        # 评估移除包
        removed_packages = self.result.removed_packages
        if removed_packages:
            removed_ratio = len(removed_packages) / baseline_count
            penalty = min(max_score * 0.3, max_score * 0.08 * removed_ratio * 10)
            score -= penalty
            
            if len(removed_packages) > 10:
                details.append(f"大量移除包({len(removed_packages)}个)可能影响功能稳定性")
                impact_factors.append("大量移除依赖")
            elif len(removed_packages) > 0:
                details.append(f"移除了{len(removed_packages)}个包")
        
        # 评估依赖关系变更
        dependency_changes = self.result.dependency_changes
        if dependency_changes:
            change_ratio = len(dependency_changes) / baseline_count
            penalty = min(max_score * 0.3, max_score * 0.05 * change_ratio * 10)
            score -= penalty
            
            if len(dependency_changes) > 5:
                details.append(f"大量依赖关系变更({len(dependency_changes)}个)可能增加兼容性风险")
                impact_factors.append("依赖关系结构变更")
            elif len(dependency_changes) > 0:
                details.append(f"发生了{len(dependency_changes)}处依赖关系变更")
        
        # 确保分数不为负
        score = max(0, score)
        
        # 如果没有问题，添加积极评价
        if score > max_score * 0.8 and not impact_factors:
            details.append("依赖结构相对稳定，变更较少")
        
        return ScoreCategory(
            name="依赖完整性",
            score=score,
            max_score=max_score,
            details=details,
            impact_factors=impact_factors
        )
    
    def _score_version_consistency(self) -> ScoreCategory:
        """评估版本一致性"""
        max_score = self.max_scores["version_consistency"]
        score = max_score
        details = []
        impact_factors = []
        
        # 基线包数量
        baseline_count = max(1, len(self.result.sbom_a.packages))
        
        # 评估版本变更
        version_changes = self.result.version_changes
        if version_changes:
            # 计算版本变更比例
            change_ratio = len(version_changes) / baseline_count
            
            # 按版本变更类型分类
            major_changes = [c for c in version_changes if c.is_major]
            minor_changes = [c for c in version_changes if c.is_minor]
            patch_changes = [c for c in version_changes if c.is_patch]
            other_changes = [c for c in version_changes if not (c.is_major or c.is_minor or c.is_patch)]
            
            # 主版本变更扣分较多
            if major_changes:
                major_ratio = len(major_changes) / baseline_count
                penalty = min(max_score * 0.5, max_score * 0.1 * major_ratio * 10)
                score -= penalty
                details.append(f"{len(major_changes)}个包发生主版本变更，可能存在API不兼容")
                impact_factors.append("主版本变更")
            
            # 次版本变更扣分中等
            if minor_changes:
                minor_ratio = len(minor_changes) / baseline_count
                penalty = min(max_score * 0.3, max_score * 0.06 * minor_ratio * 10)
                score -= penalty
                details.append(f"{len(minor_changes)}个包发生次版本变更")
                if len(minor_changes) > 5:
                    impact_factors.append("大量次版本变更")
            
            # 补丁版本变更扣分较少
            if patch_changes:
                patch_ratio = len(patch_changes) / baseline_count
                penalty = min(max_score * 0.2, max_score * 0.03 * patch_ratio * 10)
                score -= penalty
                details.append(f"{len(patch_changes)}个包发生补丁版本变更")
            
            # 其他版本变更
            if other_changes:
                other_ratio = len(other_changes) / baseline_count
                penalty = min(max_score * 0.2, max_score * 0.04 * other_ratio * 10)
                score -= penalty
                details.append(f"{len(other_changes)}个包发生其他版本变更")
        
            # 检测版本降级（特别严重的问题）
            downgrades = []
            for change in version_changes:
                try:
                    old_parts = [int(p.split('-')[0]) for p in change.old_version.split('.')]
                    new_parts = [int(p.split('-')[0]) for p in change.new_version.split('.')]
                    
                    for i in range(min(len(old_parts), len(new_parts))):
                        if new_parts[i] < old_parts[i]:
                            downgrades.append(change.package_name)
                            break
                        elif new_parts[i] > old_parts[i]:
                            break
                except (ValueError, IndexError):
                    continue
            
            if downgrades:
                penalty = min(max_score * 0.7, len(downgrades) * max_score * 0.1)
                score -= penalty
                details.append(f"{len(downgrades)}个包发生版本降级，可能丢失安全修复")
                impact_factors.append("版本降级")
        
        # 确保分数不为负
        score = max(0, score)
        
        # 如果没有问题，添加积极评价
        if score > max_score * 0.8 and not impact_factors:
            details.append("版本变更合理，主要是补丁和小版本更新")
        
        return ScoreCategory(
            name="版本一致性",
            score=score,
            max_score=max_score,
            details=details,
            impact_factors=impact_factors
        )
    
    def _score_license_compliance(self) -> ScoreCategory:
        """评估许可证合规性"""
        max_score = self.max_scores["license_compliance"]
        score = max_score
        details = []
        impact_factors = []
        
        # 基线包数量
        baseline_count = max(1, len(self.result.sbom_a.packages))
        
        # 评估许可证变更
        license_changes = self.result.license_changes
        if license_changes:
            # 许可证变更比例
            change_ratio = len(license_changes) / baseline_count
            penalty = min(max_score * 0.4, max_score * 0.08 * change_ratio * 10)
            score -= penalty
            
            details.append(f"{len(license_changes)}个包发生许可证变更")
            
            # 兼容性问题（严重扣分）
            incompatible_changes = [c for c in license_changes if c.compatibility_issue]
            if incompatible_changes:
                penalty = min(max_score * 0.6, len(incompatible_changes) * max_score * 0.15)
                score -= penalty
                details.append(f"{len(incompatible_changes)}个包存在许可证兼容性问题")
                impact_factors.append("许可证兼容性问题")
            
            # 从开源到商业/专有许可证变更
            opensrc_to_commercial = []
            for change in license_changes:
                if (change.old_license and change.new_license and 
                    any(oss in change.old_license.upper() for oss in ["MIT", "BSD", "APACHE", "GPL"]) and 
                    any(comm in change.new_license.upper() for comm in ["PROPRIETARY", "COMMERCIAL"])):
                    opensrc_to_commercial.append(change.package_name)
            
            if opensrc_to_commercial:
                penalty = min(max_score * 0.5, len(opensrc_to_commercial) * max_score * 0.1)
                score -= penalty
                details.append(f"{len(opensrc_to_commercial)}个包从开源许可证变更为商业/专有许可证")
                impact_factors.append("开源到商业许可证变更")
        
        # 检查新增包中缺少许可证的情况
        missing_license = []
        for pkg_name in self.result.added_packages:
            pkg = self.result.sbom_b.get_package_by_name(pkg_name)
            if pkg and not pkg.license_concluded:
                missing_license.append(pkg_name)
        
        if missing_license:
            penalty = min(max_score * 0.4, len(missing_license) * max_score * 0.08)
            score -= penalty
            details.append(f"{len(missing_license)}个新增包缺少许可证信息")
            impact_factors.append("缺少许可证信息")
        
        # 确保分数不为负
        score = max(0, score)
        
        # 如果没有问题，添加积极评价
        if score > max_score * 0.8 and not impact_factors:
            details.append("许可证变更较少，无明显合规风险")
        
        return ScoreCategory(
            name="许可证合规性",
            score=score,
            max_score=max_score,
            details=details,
            impact_factors=impact_factors
        )
    
    def _score_supply_chain_integrity(self) -> ScoreCategory:
        """评估供应链完整性"""
        max_score = self.max_scores["supply_chain_integrity"]
        score = max_score
        details = []
        impact_factors = []
        
        # 基线包数量
        baseline_count = max(1, len(self.result.sbom_a.packages))
        
        # 评估供应商变更
        supplier_changes = self.result.supplier_changes
        if supplier_changes:
            change_ratio = len(supplier_changes) / baseline_count
            penalty = min(max_score * 0.5, max_score * 0.1 * change_ratio * 10)
            score -= penalty
            
            if len(supplier_changes) > 5:
                details.append(f"大量供应商变更({len(supplier_changes)}个)可能表明供应链重定向")
                impact_factors.append("供应链重定向")
            else:
                details.append(f"{len(supplier_changes)}个包的供应商发生变更")
        
        # 根据SBOM比较类型进行特定评分
        if self.source_type == "source_to_ci":
            # 在CI阶段新增的未定义包是严重问题
            if self.result.added_packages:
                ratio = len(self.result.added_packages) / baseline_count
                penalty = min(max_score * 0.6, max_score * 0.12 * ratio * 10)
                score -= penalty
                details.append(f"CI阶段新增了{len(self.result.added_packages)}个在源代码中未定义的包")
                impact_factors.append("CI阶段引入未授权包")
        
        elif self.source_type == "ci_to_container":
            # 容器中缺失的包是严重问题
            if self.result.removed_packages:
                ratio = len(self.result.removed_packages) / baseline_count
                penalty = min(max_score * 0.7, max_score * 0.14 * ratio * 10)
                score -= penalty
                details.append(f"容器镜像中缺少{len(self.result.removed_packages)}个在CI构建中存在的包")
                impact_factors.append("容器缺失必要依赖")
            
            # 容器中新增的包也需关注
            if self.result.added_packages:
                ratio = len(self.result.added_packages) / baseline_count
                penalty = min(max_score * 0.5, max_score * 0.1 * ratio * 10)
                score -= penalty
                details.append(f"容器镜像中包含{len(self.result.added_packages)}个在CI构建中未出现的包")
                impact_factors.append("容器引入额外依赖")
        
        elif self.source_type == "source_to_container":
            # 源代码到容器的变化，特别关注新增包
            if self.result.added_packages:
                ratio = len(self.result.added_packages) / baseline_count
                penalty = min(max_score * 0.6, max_score * 0.12 * ratio * 10)
                score -= penalty
                details.append(f"容器中存在{len(self.result.added_packages)}个在源代码中未声明的包")
                impact_factors.append("端到端额外依赖引入")
        
        # 确保分数不为负
        score = max(0, score)
        
        # 如果没有问题，添加积极评价
        if score > max_score * 0.8 and not impact_factors:
            if self.source_type == "source_to_ci":
                details.append("CI阶段保持了与源代码定义的依赖一致性")
            elif self.source_type == "ci_to_container":
                details.append("容器镜像正确包含了CI阶段构建的所有组件")
            elif self.source_type == "source_to_container":
                details.append("从源代码到容器的整个供应链保持了高度完整性")
            else:
                details.append("供应链保持了较高的完整性，无明显篡改迹象")
        
        return ScoreCategory(
            name="供应链完整性",
            score=score,
            max_score=max_score,
            details=details,
            impact_factors=impact_factors
        )
    
    def _score_risk_assessment(self) -> ScoreCategory:
        """评估风险评估结果"""
        max_score = self.max_scores["risk_assessment"]
        score = max_score
        details = []
        impact_factors = []
        
        # 重新检查是否有风险分析结果，不仅依赖初始化时的检查
        has_risks = hasattr(self.result, "risks")
        
        # 仅在有风险分析结果时评分
        if has_risks:
            # 高风险项
            high_risks = self.result.risks.get("high", [])
            if high_risks:
                penalty = min(max_score * 0.7, len(high_risks) * max_score * 0.15)
                score -= penalty
                details.append(f"存在{len(high_risks)}个高风险项")
                
                # 分析高风险类型
                risk_types = set(risk.category for risk in high_risks)
                if risk_types:
                    impact_factors.extend(list(risk_types)[:3])  # 最多添加前3个
            
            # 中风险项
            medium_risks = self.result.risks.get("medium", [])
            if medium_risks:
                penalty = min(max_score * 0.5, len(medium_risks) * max_score * 0.08)
                score -= penalty
                details.append(f"存在{len(medium_risks)}个中风险项")
                
                # 如果前面没有高风险，添加中风险类型
                if not impact_factors:
                    risk_types = set(risk.category for risk in medium_risks)
                    if risk_types:
                        impact_factors.extend(list(risk_types)[:2])  # 最多添加前2个
            
            # 低风险项
            low_risks = self.result.risks.get("low", [])
            if low_risks:
                penalty = min(max_score * 0.3, len(low_risks) * max_score * 0.05)
                score -= penalty
                details.append(f"存在{len(low_risks)}个低风险项")
        else:
            # 无风险分析数据，给予中等评分
            score = max_score * 0.7
            details.append("无详细风险分析数据")
            impact_factors.append("缺少风险分析")
        
        # 确保分数不为负
        score = max(0, score)
        
        # 如果风险很少或没有，添加积极评价
        if has_risks and score > max_score * 0.8 and not impact_factors:
            details.append("风险分析未发现明显的安全问题")
        
        return ScoreCategory(
            name="风险评估",
            score=score,
            max_score=max_score,
            details=details,
            impact_factors=impact_factors
        )
    
    def _score_scorecard_assessment(self) -> ScoreCategory:
        """评估Scorecard得分"""
        max_score = self.max_scores["scorecard_assessment"]
        score = 0.0
        details = []
        impact_factors = []
        
        if self.scorecard_score is not None:
            # Scorecard评分范围是0-10，直接使用
            score = (self.scorecard_score / 10.0) * max_score
            
            # 获取重要检查项状态
            if self.scorecard_details:
                check_scores = self.scorecard_api.get_check_scores(self.scorecard_details)
                important_checks = self.scorecard_api.get_important_checks(check_scores)
                
                # 添加重要检查项的状态到详情
                risk_items = []
                for check, status in important_checks.items():
                    if status == "风险较高":
                        risk_items.append(check)
                        impact_factors.append(f"{check}风险")
                    elif status == "需要改进":
                        details.append(f"{check}需要改进")
                
                if risk_items:
                    details.append(f"以下项目风险较高: {', '.join(risk_items)}")
                
                # 提取并添加漏洞信息
                vulnerabilities = self.scorecard_api.get_vulnerability_details(self.scorecard_details)
                if vulnerabilities:
                    details.append("\n已知漏洞信息:")
                    for vuln in vulnerabilities:
                        severity_color = {
                            "CRITICAL": "严重",
                            "HIGH": "高危",
                            "MEDIUM": "中危",
                            "LOW": "低危",
                            "unknown": "未知"
                        }.get(vuln["severity"], "未知")
                        details.append(f"- {vuln['id']} ({severity_color}): {vuln['description']}")
                    impact_factors.append("存在已知漏洞")
                
                # 根据Scorecard评分添加总体评价
                if self.scorecard_score >= 8.0:
                    details.append("项目整体安全实践良好")
                elif self.scorecard_score >= 6.0:
                    details.append("项目安全实践有待改进")
                else:
                    details.append("项目安全实践亟需加强")
                    impact_factors.append("整体安全实践不足")
        else:
            score = max_score * 0.6  # 如果无法获取Scorecard评分，给予基础分
            details.append("无法获取Scorecard评分数据")
            impact_factors.append("缺少Scorecard评估")
        
        return ScoreCategory(
            name="Scorecard评估",
            score=score,
            max_score=max_score,
            details=details,
            impact_factors=impact_factors
        )
    
    def _calculate_grade(self, score: float, max_score: float) -> str:
        """计算安全等级"""
        percentage = (score / max_score) * 100 if max_score > 0 else 0
        
        if percentage >= 90:
            return "A+"  # 优秀
        elif percentage >= 85:
            return "A"   # 非常好
        elif percentage >= 80:
            return "A-"  # 良好+
        elif percentage >= 75:
            return "B+"  # 良好
        elif percentage >= 70:
            return "B"   # 一般
        elif percentage >= 65:
            return "B-"  # 一般-
        elif percentage >= 60:
            return "C+"  # 及格+
        elif percentage >= 55:
            return "C"   # 及格
        elif percentage >= 50:
            return "C-"  # 及格-
        elif percentage >= 40:
            return "D"   # 差
        else:
            return "F"   # 不及格
    
    def _generate_summary(self, total_score: float, max_score: float, 
                           grade: str, categories: Dict[str, ScoreCategory]) -> str:
        """生成评分总结"""
        percentage = (total_score / max_score) * 100 if max_score > 0 else 0
        
        # 收集主要影响因素
        all_factors = []
        for category in categories.values():
            all_factors.extend(category.impact_factors)
        
        # 获取主要影响因素（最多5个）
        main_factors = all_factors[:5] if all_factors else []
        
        # 构建总结
        if self.source_type == "source_to_ci":
            stage_desc = "源代码到CI阶段"
        elif self.source_type == "ci_to_container":
            stage_desc = "CI到容器阶段"
        elif self.source_type == "source_to_container":
            stage_desc = "源代码到容器的端到端"
        else:
            stage_desc = ""
        
        summary = f"软件供应链{stage_desc}安全评分为 {total_score:.1f}/{max_score:.1f} ({percentage:.1f}%)，安全等级: {grade}。"
        
        # 添加评分解释
        if percentage >= 80:
            summary += " 软件供应链保持了较高的完整性和一致性。"
        elif percentage >= 60:
            summary += " 软件供应链总体安全性可接受，但存在一些需要关注的问题。"
        else:
            summary += " 软件供应链安全风险较高，需要采取措施改进。"
        
        # 添加主要影响因素
        if main_factors:
            summary += f" 主要影响因素：{', '.join(main_factors)}。"
        
        return summary 