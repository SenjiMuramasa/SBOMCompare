#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM报告生成器 - 生成SBOM比较报告
"""

import os
import json
import logging
import re
import requests
import time
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import matplotlib.pyplot as plt
import networkx as nx
from tabulate import tabulate
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from lxml import html
from tqdm import tqdm
import copy

from .comparator import ComparisonResult

# 初始化colorama
init()

logger = logging.getLogger("sbom-compare.report")

class ReportGenerator:
    """报告生成器类"""
    
    def __init__(self, comparison_result: ComparisonResult):
        """
        初始化报告生成器
        
        Args:
            comparison_result: SBOM比较结果
        """
        self.result = comparison_result
        self.sbom_a = comparison_result.sbom_a
        self.sbom_b = comparison_result.sbom_b

    
    def generate(self, output_path: str, format_type: str = "text") -> None:
        """生成报告
        
        Args:
            output_path: 报告输出路径
            format_type: 报告格式，可以是 'text', 'html', 或 'json'
        """
        start_time = time.time()
        logger.info(f"开始生成{format_type}格式报告: {output_path}")
        
        if format_type == "text":
            print(f"生成文本报告...")
            self._generate_text_report(output_path)
        elif format_type == "html":
            print(f"生成HTML报告...")
            self._generate_html_report(output_path)
        elif format_type == "json":
            print(f"生成JSON报告...")
            self._generate_json_report(output_path)
        else:
            logger.error(f"不支持的报告格式: {format_type}")
            raise ValueError(f"不支持的报告格式: {format_type}")
            
        end_time = time.time()
        elapsed = end_time - start_time
        logger.info(f"报告生成完成，耗时 {elapsed:.2f} 秒")
        print(f"✅ 报告生成完成！文件保存在: {output_path}")
        print(f"   总耗时: {elapsed:.2f} 秒")
    
    def _generate_text_report(self, output_path: str) -> None:
        """生成文本格式的报告"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self._get_text_report_content())
    
    def _get_text_report_content(self) -> str:
        """获取文本报告内容"""
        lines = []
        
        # 报告标题
        lines.append("=" * 80)
        lines.append("SBOM 比较报告")
        lines.append("=" * 80)
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"SBOM A: {self.sbom_a.file_path}")
        lines.append(f"SBOM B: {self.sbom_b.file_path}")
        lines.append("")
        
        # 安全评分(如果有)
        if hasattr(self.result, "security_score"):
            security_score = self.result.security_score
            lines.append("-" * 80)
            lines.append("软件供应链安全评分 (满分10分)")
            lines.append("-" * 80)
            percentage = (security_score.total_score / security_score.max_score) * 100
            lines.append(f"总评分: {security_score.total_score:.1f}/10 "
                         f"({percentage:.1f}%) [{security_score.grade}]")
            
            lines.append("\n分类评分:")
            for category_name, category in security_score.categories.items():
                cat_percentage = (category.score / category.max_score) * 100
                lines.append(f"  {category.name}: {category.score:.1f}/{category.max_score:.1f} "
                             f"({cat_percentage:.1f}%)")
                
                # 详情和影响因素
                if category.details:
                    lines.append("    详情:")
                    for detail in category.details:
                        lines.append(f"      - {detail}")
                if category.impact_factors:
                    lines.append(f"    影响因素: {', '.join(category.impact_factors)}")
            
            lines.append(f"\n评分总结: {security_score.summary}")
            
            # 添加重要警告信息部分
            critical_warnings = []
            # 检查是否有版本降级
            for category_name, category in security_score.categories.items():
                if category_name == "version_consistency":
                    for detail in category.details:
                        if "降级" in detail:
                            critical_warnings.append(detail)
            
            # 显示关键警告信息
            if critical_warnings:
                lines.append("\n重要警告:")
                for warning in critical_warnings:
                    lines.append(f"  ⚠️ {warning}")
            
            lines.append("")
        
        # 基本统计信息
        lines.append("-" * 80)
        lines.append("基本统计信息")
        lines.append("-" * 80)
        lines.append(f"包数量 A: {len(self.sbom_a.packages)}, B: {len(self.sbom_b.packages)}")
        lines.append(f"新增包: {len(self.result.added_packages)}")
        lines.append(f"移除包: {len(self.result.removed_packages)}")
        lines.append(f"版本变更: {len(self.result.version_changes)}")
        lines.append(f"许可证变更: {len(self.result.license_changes)}")
        lines.append(f"供应商变更: {len(self.result.supplier_changes)}")
        lines.append(f"依赖关系变更: {len(self.result.dependency_changes)}")

        # 文件统计
        if hasattr(self.result, 'added_files') and hasattr(self.result, 'removed_files'):
            file_count_a = len(self.sbom_a.file_map) if hasattr(self.sbom_a, 'file_map') else 0
            file_count_b = len(self.sbom_b.file_map) if hasattr(self.sbom_b, 'file_map') else 0
            lines.append(f"文件数量 A: {file_count_a}, B: {file_count_b}")
            lines.append(f"新增文件: {len(self.result.added_files)}")
            lines.append(f"移除文件: {len(self.result.removed_files)}")
            lines.append(f"文件内容变更: {len(self.result.file_changes)}")
        
        lines.append("")
        
        # 新增包
        if self.result.added_packages:
            lines.append("-" * 80)
            lines.append("新增包")
            lines.append("-" * 80)
            for pkg_name in self.result.added_packages:
                pkg = self.sbom_b.get_package_by_name(pkg_name)
                version = pkg.version if pkg and pkg.version else "未知"
                license_name = pkg.license_concluded if pkg and pkg.license_concluded else "未知"
                lines.append(f"{pkg_name} (版本: {version}, 许可证: {license_name})")
            lines.append("")
        
        # 移除包
        if self.result.removed_packages:
            lines.append("-" * 80)
            lines.append("移除包")
            lines.append("-" * 80)
            for pkg_name in self.result.removed_packages:
                pkg = self.sbom_a.get_package_by_name(pkg_name)
                version = pkg.version if pkg and pkg.version else "未知"
                license_name = pkg.license_concluded if pkg and pkg.license_concluded else "未知"
                lines.append(f"{pkg_name} (版本: {version}, 许可证: {license_name})")
            lines.append("")
        
        # 版本变更
        if self.result.version_changes:
            lines.append("-" * 80)
            lines.append("版本变更")
            lines.append("-" * 80)
            table_data = []
            headers = ["包名", "旧版本", "新版本", "变更类型"]
            
            # 检测版本降级
            downgrades = []
            for change in self.result.version_changes:
                # 规范化版本号进行比较
                normalized_old = self._normalize_version(change.old_version)
                normalized_new = self._normalize_version(change.new_version)
                
                # 当规范化后的版本相同时显示为"无变更"
                if normalized_old == normalized_new:
                    change_type = "无变更"
                else:
                    # 检查是否为降级
                    is_downgrade = False
                    try:
                        old_parts = [int(p.split('-')[0]) for p in normalized_old.split('.')]
                        new_parts = [int(p.split('-')[0]) for p in normalized_new.split('.')]
                        
                        for i in range(min(len(old_parts), len(new_parts))):
                            if new_parts[i] < old_parts[i]:
                                is_downgrade = True
                                downgrades.append(change.package_name)
                                break
                            elif new_parts[i] > old_parts[i]:
                                break
                    except (ValueError, IndexError):
                        pass
                    
                    if is_downgrade:
                        change_type = "⚠️ 版本降级"
                    else:
                        change_type = "主版本" if change.is_major else "次版本" if change.is_minor else "补丁版本" if change.is_patch else "一般变更"
                
                table_data.append([
                    change.package_name,
                    change.old_version,
                    change.new_version,
                    change_type
                ])
            
            lines.append(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            # 如果存在版本降级，添加警告
            if downgrades:
                lines.append("")
                lines.append("⚠️ 警告: 检测到以下包版本降级，可能丢失安全修复或引入兼容性问题:")
                for pkg in downgrades:
                    lines.append(f"  - {pkg}")
            
            lines.append("")
            
            # 添加版本变更引入的漏洞信息
            version_changed_vulnerabilities = self._check_version_changed_vulnerabilities()
            if version_changed_vulnerabilities:
                lines.append("-" * 80)
                lines.append("版本变更引入的漏洞")
                lines.append("-" * 80)
                vuln_table_data = []
                vuln_headers = ["包名", "漏洞ID", "严重程度", "版本范围", "描述"]
                
                for pkg_name, vulns in version_changed_vulnerabilities.items():
                    for vuln in vulns:
                        # 提取基本信息
                        vuln_id = vuln.get("id", "未知")
                        severity = "未知"
                        if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                            severity = vuln["database_specific"]["severity"]
                        
                        # 获取版本范围
                        affected_versions = "未知"
                        if "affected" in vuln:
                            for affected in vuln["affected"]:
                                if "versions" in affected:
                                    affected_versions = ", ".join(affected["versions"])
                                    break
                        
                        # 获取描述
                        description = vuln.get("summary", "无描述")
                        
                        # 添加到表格
                        vuln_table_data.append([
                            pkg_name,
                            vuln_id,
                            severity,
                            affected_versions,
                            description[:100] + "..." if len(description) > 100 else description
                        ])
                
                if vuln_table_data:
                    lines.append(tabulate(vuln_table_data, headers=vuln_headers, tablefmt="grid"))
                else:
                    lines.append("未发现版本变更引入的漏洞")
                lines.append("")
        
        # 许可证变更
        if self.result.license_changes:
            lines.append("-" * 80)
            lines.append("许可证变更")
            lines.append("-" * 80)
            table_data = []
            headers = ["包名", "旧许可证", "新许可证", "兼容性问题"]
            
            for change in self.result.license_changes:
                table_data.append([
                    change.package_name,
                    change.old_license,
                    change.new_license,
                    "是" if change.compatibility_issue else "否"
                ])
            
            lines.append(tabulate(table_data, headers=headers, tablefmt="grid"))
            lines.append("")
        
        # 供应商变更
        if self.result.supplier_changes:
            lines.append("-" * 80)
            lines.append("供应商变更")
            lines.append("-" * 80)
            table_data = []
            headers = ["包名", "旧供应商", "新供应商"]
            
            for change in self.result.supplier_changes:
                table_data.append([
                    change.package_name,
                    change.old_supplier,
                    change.new_supplier
                ])
            
            lines.append(tabulate(table_data, headers=headers, tablefmt="grid"))
            lines.append("")
        
        # 风险分析
        if hasattr(self.result, "risks"):
            lines.append("-" * 80)
            lines.append("风险分析")
            lines.append("-" * 80)
            
            # 收集所有风险，按阶段和级别进行分组
            all_stages = {"source": [], "ci": [], "container": [], "end-to-end": [], None: []}
            
            risk_levels = ["high", "medium", "low"]
            for level in risk_levels:
                if level in self.result.risks and self.result.risks[level]:
                    # 按供应链阶段分组
                    stage_risks = self._group_risks_by_stage(self.result.risks[level])
                    
                    # 将风险按阶段收集，并保留级别信息
                    for stage, risks in stage_risks.items():
                        if stage in all_stages:
                            for risk in risks:
                                all_stages[stage].append((level, risk))
            
            
            # 先处理通用风险（没有特定阶段）
            risk_items = []
            if all_stages[None]:
                # 添加通用风险标题
                risk_items.append(f"""
                <div class="stage-header">
                    <span>【通用风险】</span>
                </div>
                """)
                
                # 按风险级别排序（高到低）
                general_risks = sorted(all_stages[None], key=lambda x: 
                                    0 if x[0] == "high" else 
                                    1 if x[0] == "medium" else 2)
                
                for level, risk in general_risks:
                    # 生成受影响的包列表
                    affected_packages = ""
                    if risk.affected_packages:
                        # 最多显示5个包
                        display_packages = risk.affected_packages[:5]
                        affected_packages = ", ".join(display_packages)
                        
                        # 如果超过5个，显示总数
                        if len(risk.affected_packages) > 5:
                            affected_packages += f"... 等共{len(risk.affected_packages)}个包"
                    
                    risk_items.append(f"""
                    <div class="risk-{level}">
                        <div class="risk-category">{risk.category}</div>
                        <div class="risk-description">{risk.description}</div>
                        <div class="risk-affected"><strong>受影响的包:</strong> {affected_packages}</div>
                        <div class="risk-recommendation"><strong>建议:</strong> {risk.recommendation}</div>
                    </div>
                    """)
            
            # 处理按阶段分组的风险
            stages = ["source", "ci", "container", "end-to-end"]
            for stage in stages:
                if all_stages[stage]:  # 如果该阶段有风险
                    stage_name = self._get_stage_name(stage)
                    # 只添加一次阶段标题
                    risk_items.append(f"""
                    <div class="stage-header">
                        <span>【{stage_name}阶段】</span>
                    </div>
                    """)
                    
                    # 按风险级别排序（高到低）
                    stage_risks = sorted(all_stages[stage], key=lambda x: 
                                        0 if x[0] == "high" else 
                                        1 if x[0] == "medium" else 2)
                    
                    for level, risk in stage_risks:
                        # 生成受影响的包列表
                        affected_packages = ""
                        if risk.affected_packages:
                            # 最多显示5个包
                            display_packages = risk.affected_packages[:5]
                            affected_packages = ", ".join(display_packages)
                            
                            # 如果超过5个，显示总数
                            if len(risk.affected_packages) > 5:
                                affected_packages += f"... 等共{len(risk.affected_packages)}个包"
                        
                        risk_items.append(f"""
                        <div class="risk-{level}">
                            <div class="risk-category">{risk.category}</div>
                            <div class="risk-description">{risk.description}</div>
                            <div class="risk-affected"><strong>受影响的包:</strong> {affected_packages}</div>
                            <div class="risk-recommendation"><strong>建议:</strong> {risk.recommendation}</div>
                        </div>
                        """)
            
            # 将风险项添加到HTML中
            for item in risk_items:
                lines.append(item)
        
        # 文件变更
        if hasattr(self.result, 'added_files') and self.result.added_files:
            lines.append("-" * 80)
            lines.append("新增文件")
            lines.append("-" * 80)
            for file_name in self.result.added_files[:50]:  # 限制显示数量
                lines.append(f"{file_name}")
            
            if len(self.result.added_files) > 50:
                lines.append(f"...等共 {len(self.result.added_files)} 个文件")
            
            lines.append("")
        
        if hasattr(self.result, 'removed_files') and self.result.removed_files:
            lines.append("-" * 80)
            lines.append("移除文件")
            lines.append("-" * 80)
            for file_name in self.result.removed_files[:50]:  # 限制显示数量
                lines.append(f"{file_name}")
            
            if len(self.result.removed_files) > 50:
                lines.append(f"...等共 {len(self.result.removed_files)} 个文件")
            
            lines.append("")
        
        if hasattr(self.result, 'file_changes') and self.result.file_changes:
            lines.append("-" * 80)
            lines.append("文件内容变更")
            lines.append("-" * 80)
            table_data = []
            headers = ["文件名", "变更类型"]
            
            for change in self.result.file_changes[:50]:  # 限制显示数量
                table_data.append([
                    change.file_name,
                    "内容变更" if change.has_content_change else "校验和变更"
                ])
            
            lines.append(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            if len(self.result.file_changes) > 50:
                lines.append(f"...等共 {len(self.result.file_changes)} 个文件内容变更")
            
            lines.append("")
        
        # 添加漏洞信息部分
        if hasattr(self.result, "security_score"):
            security_score = self.result.security_score
            scorecard_category = security_score.categories.get("scorecard_assessment")
            if scorecard_category:
                vulnerabilities = self._process_vulnerabilities(scorecard_category)
                
                if vulnerabilities:
                    lines.append("\n漏洞信息:")
                    lines.append("-" * 80)
                    for vuln in vulnerabilities:
                        lines.append(vuln["description"])
                    lines.append("")
        
        return "\n".join(lines)
    
    def _group_risks_by_stage(self, risks):
        """按供应链阶段分组风险"""
        grouped = {}
        for risk in risks:
            stage = getattr(risk, "supply_chain_stage", None)
            if stage not in grouped:
                grouped[stage] = []
            grouped[stage].append(risk)
        return grouped
    
    def _get_stage_name(self, stage):
        """获取供应链阶段的中文名称"""
        stage_names = {
            "source": "源代码",
            "ci": "CI/CD",
            "container": "容器镜像",
            "end-to-end": "端到端供应链"
        }
        return stage_names.get(stage, stage)
    
    def _fetch_vuln_info(self, vuln_id: str) -> Dict:
        """
        通过旧的OSV API获取漏洞详细信息
        
        Args:
            vuln_id: 漏洞ID
            
        Returns:
            Dict: 漏洞详细信息，如果查询失败返回空字典
        """
        # 清理ID，确保没有前缀
        vuln_id = self._clean_vulnerability_id(vuln_id)
        
        # 如果包含/，则使用第一个ID作为主ID
        if "/" in vuln_id:
            vuln_id = vuln_id.split(" / ")[0].strip()
        
        # 重试参数
        max_retries = 3
        retry_delay = 2  # 初始延迟2秒
        
        # 带重试的API请求
        for attempt in range(max_retries):
            try:
                # 构建OSV API查询URL
                url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
                
                # 如果不是第一次尝试，添加延迟
                if attempt > 0:
                    sleep_time = retry_delay * (2 ** (attempt - 1))
                    logger.info(f"重试查询漏洞 {vuln_id} 的详细信息 (第{attempt+1}次尝试)，等待 {sleep_time} 秒")
                    time.sleep(sleep_time)
                
                # 发送GET请求
                response = requests.get(url, timeout=15)
                
                # 检查响应
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    logger.warning(f"未找到漏洞 {vuln_id} 的详细信息")
                    return {}
                else:
                    logger.warning(f"查询漏洞 {vuln_id} 详细信息失败，状态码: {response.status_code}")
                    
                    # 如果是最后一次尝试，放弃并返回空字典
                    if attempt == max_retries - 1:
                        return {}
            except Exception as e:
                logger.error(f"查询漏洞 {vuln_id} 详细信息时出错: {str(e)}")
                
                # 如果是最后一次尝试，放弃并返回空字典
                if attempt == max_retries - 1:
                    return {}
        
        return {}
    
    def _fetch_vuln_batch(self, vuln_ids: List[str]) -> Dict[str, Optional[Dict]]:
        """
        批量获取漏洞详细信息
        
        Args:
            vuln_ids: 漏洞ID列表
            
        Returns:
            Dict[str, Optional[Dict]]: 漏洞ID到详细信息的映射
        """
        results = {}
        
        # 创建进度条
        with tqdm(total=len(vuln_ids), desc="获取漏洞详情", unit="个") as pbar:
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_id = {executor.submit(self._fetch_vuln_info, vuln_id): vuln_id for vuln_id in vuln_ids}
                
                for future in as_completed(future_to_id):
                    vuln_id = future_to_id[future]
                    try:
                        vuln_data = future.result()
                        results[vuln_id] = vuln_data
                    except Exception as e:
                        logger.error(f"获取漏洞 {vuln_id} 详细信息失败: {str(e)}")
                        results[vuln_id] = None
                    finally:
                        pbar.update(1)
        
        return results
    
    def _fetch_cve_info(self, cve_id: str) -> Optional[Dict]:
        """从CVE API获取CVE详细信息
        
        Args:
            cve_id: CVE ID(如CVE-2021-44228)
            
        Returns:
            Optional[Dict]: CVE详细信息，如果获取失败则返回None
        """
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"获取CVE {cve_id} 信息失败，状态码: {response.status_code}")
        except Exception as e:
            logger.error(f"获取CVE {cve_id} 信息时出错: {str(e)}")
        return None
    
    def _fetch_cve_info_batch(self, cve_ids: List[str]) -> Dict[str, Optional[Dict]]:
        """批量从CVE API获取漏洞详细信息
        
        Args:
            cve_ids: CVE标识符列表
            
        Returns:
            Dict[str, Optional[Dict]]: 包含CVE ID和对应详细信息的字典
        """
        results = {}
        
        # 创建进度条
        with tqdm(total=len(cve_ids), desc="获取CVE详情", unit="个") as pbar:
            # 使用线程池并行获取所有CVE信息
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_cve = {executor.submit(self._fetch_cve_info, cve_id): cve_id for cve_id in cve_ids}
                
                for future in as_completed(future_to_cve):
                    cve_id = future_to_cve[future]
                    try:
                        cve_data = future.result()
                        results[cve_id] = cve_data
                    except Exception as e:
                        print(f"Error fetching CVE info for {cve_id}: {str(e)}")
                        results[cve_id] = None
                    finally:
                        pbar.update(1)
        
        return results
    
    def _enhance_with_cve_info(self, description: str, osv_data: Dict) -> str:
        """
        增强漏洞描述信息，添加来自CVE的详情
        
        Args:
            description: 原始描述文本
            osv_data: OSV API响应数据
            
        Returns:
            str: 增强后的描述文本
        """
        if not osv_data:
            return self._escape_html_tags(description)
        
        # 从OSV数据中提取CVE ID
        cve_ids = []
        if "aliases" in osv_data:
            cve_ids = [id for id in osv_data["aliases"] if id.startswith("CVE-")]
        
        # 如果没有CVE ID，直接返回
        if not cve_ids:
            return self._escape_html_tags(description)
        
        # 构建增强的描述
        enhanced_description = description
        
        # 为每个CVE ID获取详细信息
        for cve_id in cve_ids:
            cve_info = self._fetch_cve_info(cve_id)
            
            if not cve_info:
                continue
            
            # 添加来自CVE的信息
            enhanced_description += f"\n\n来自 {cve_id} 的附加信息:"
            
            # 提取描述
            if "descriptions" in cve_info and cve_info["descriptions"]:
                for desc in cve_info["descriptions"]:
                    if desc.get("lang") == "en":
                        enhanced_description += f"\n描述: {self._escape_html_tags(desc.get('value', ''))}"
                        break
            
            # 提取发布日期
            if "published" in cve_info:
                try:
                    published_date = cve_info["published"][:10]  # 只取年月日部分
                    enhanced_description += f"\n发布日期: {published_date}"
                except Exception:
                    pass
            
            # 提取最后更新日期
            if "lastModified" in cve_info:
                try:
                    last_modified = cve_info["lastModified"][:10]
                    enhanced_description += f"\n最后更新: {last_modified}"
                except Exception:
                    pass
            
            # 提取CVSS评分和严重程度
            if "metrics" in cve_info and "cvssMetricV31" in cve_info["metrics"]:
                for metric in cve_info["metrics"]["cvssMetricV31"]:
                    if "cvssData" in metric:
                        cvss_data = metric["cvssData"]
                        score = cvss_data.get("baseScore", "未知")
                        severity = cvss_data.get("baseSeverity", "未知")
                        enhanced_description += f"\nCVSS 3.1 评分: {score} ({severity})"
                        
                        # 添加详细的CVSS向量
                        if "vectorString" in cvss_data:
                            enhanced_description += f"\nCVSS 向量: {self._escape_html_tags(cvss_data['vectorString'])}"
                        break
            
            # 添加参考链接
            if "references" in cve_info and cve_info["references"]:
                enhanced_description += "\nCVE参考链接:"
                for ref in cve_info["references"]:
                    if "url" in ref:
                        url = ref["url"]
                        enhanced_description += f"\n- {self._escape_html_tags(url)}"
        
        return enhanced_description

    def _process_vulnerabilities(self, scorecard_category) -> List[Dict]:
        """处理Scorecard中的漏洞信息"""
        vulnerabilities = []
        if not scorecard_category:
            return vulnerabilities
        
        # 检查scorecard_category是否为ScoreCategory对象
        if hasattr(scorecard_category, 'details') and isinstance(scorecard_category.details, list):
            # 直接处理ScoreCategory对象中的details列表
            for detail in scorecard_category.details:
                # 尝试从details中提取漏洞信息
                if detail.startswith("- "):
                    # 解析漏洞信息格式，例如 "- GHSA-xxxx-xxxx-xxxx (高危): 描述"
                    vuln_info = detail[2:].strip().split(" (", 1)
                    if len(vuln_info) == 2:
                        vuln_id = vuln_info[0].strip()
                        severity_desc_parts = vuln_info[1].split("): ", 1)
                        
                        if len(severity_desc_parts) == 2:
                            severity = severity_desc_parts[0].strip()
                            description = severity_desc_parts[1].strip()
                            
                            vuln_details = {
                                'id': vuln_id,
                                'severity': severity,
                                'description': self._escape_html_tags(description)
                            }
                            
                            # 获取详细的漏洞信息
                            if vuln_id:
                                osv_data = self._fetch_vuln_with_fallback(vuln_id)
                                
                                if osv_data:
                                    # 提取漏洞描述
                                    if 'summary' in osv_data:
                                        vuln_details['description'] = self._escape_html_tags(osv_data['summary'])
                                    
                                    # 如果有detail，使用detail代替summary
                                    if 'details' in osv_data and osv_data['details']:
                                        vuln_details['description'] = self._escape_html_tags(osv_data['details'])
                                    
                                    # 添加相关漏洞ID
                                    if 'aliases' in osv_data and osv_data['aliases']:
                                        vuln_details['description'] += "\n\n相关漏洞ID: \n"
                                        for alias in osv_data['aliases']:
                                            vuln_details['description'] += f"- {alias}\n"
                                    
                                    # 添加参考链接
                                    if 'references' in osv_data and osv_data['references']:
                                        vuln_details['description'] += "\n参考链接: \n"
                                        for ref in osv_data['references']:
                                            if 'url' in ref:
                                                vuln_details['description'] += f"- {ref['url']}\n"
                                    
                                    # 添加受影响版本范围
                                    if 'affected' in osv_data and osv_data['affected']:
                                        vuln_details['description'] += "\n影响范围: \n"
                                        for affected in osv_data['affected']:
                                            if 'package' in affected and 'name' in affected['package']:
                                                package_name = affected['package']['name']
                                                if 'ranges' in affected:
                                                    for range_info in affected['ranges']:
                                                        if 'events' in range_info:
                                                            events = range_info['events']
                                                            range_str = ""
                                                            for event in events:
                                                                if 'introduced' in event:
                                                                    if event['introduced'] == "0":
                                                                        range_str += "所有版本 "
                                                                    else:
                                                                        range_str += f">= {event['introduced']} "
                                                                if 'fixed' in event:
                                                                    range_str += f"< {event['fixed']} "
                                                            vuln_details['description'] += f"- {package_name}: {range_str}\n"
                                                elif 'versions' in affected and affected['versions']:
                                                    versions = ", ".join(affected['versions'])
                                                    vuln_details['description'] += f"- {package_name}: {versions}\n"
                                                else:
                                                    vuln_details['description'] += f"- {package_name}: 未指定版本范围\n"
                                    
                                    # 提取CVE信息并增强描述
                                    if 'aliases' in osv_data:
                                        cve_ids = [id for id in osv_data['aliases'] if id.startswith('CVE-')]
                                        for cve_id in cve_ids:
                                            vuln_details['description'] = self._enhance_with_cve_info(vuln_details['description'], osv_data)
                                    
                                    # 确定严重程度
                                    if 'database_specific' in osv_data and 'severity' in osv_data['database_specific']:
                                        raw_severity = osv_data['database_specific']['severity']
                                        severity_mapping = {
                                            "CRITICAL": "严重",
                                            "HIGH": "高危",
                                            "MEDIUM": "中危",
                                            "LOW": "低危"
                                        }
                                        vuln_details['severity'] = severity_mapping.get(raw_severity, severity)
                            
                            vulnerabilities.append(vuln_details)
            
            return vulnerabilities
        
        # 如果是scorecard_details结构（如从API获取的数据）
        elif isinstance(scorecard_category, list):
            # 处理原始的scorecard_details数据结构
            for check in scorecard_category:
                if check['name'] == "Vulnerabilities" and 'findings' in check and check['findings']:
                    for finding in check['findings']:
                        vuln_id = finding.get('ID', "")
                        vuln_details = {
                            'id': vuln_id,
                            'severity': "未知",
                            'description': ""
                        }
                        
                        # 检查是否有概要信息
                        if 'message' in finding:
                            vuln_details['description'] = self._escape_html_tags(finding['message'])
                        
                        # 获取详细的漏洞信息
                        if vuln_id:
                            osv_data = self._fetch_vuln_with_fallback(vuln_id)
                            
                            if osv_data:
                                # 提取漏洞描述
                                if 'summary' in osv_data:
                                    vuln_details['description'] = self._escape_html_tags(osv_data['summary'])
                                
                                # 如果有detail，使用detail代替summary
                                if 'details' in osv_data and osv_data['details']:
                                    vuln_details['description'] = self._escape_html_tags(osv_data['details'])
                                
                                # 添加相关漏洞ID
                                if 'aliases' in osv_data and osv_data['aliases']:
                                    vuln_details['description'] += "\n\n相关漏洞ID: \n"
                                    for alias in osv_data['aliases']:
                                        vuln_details['description'] += f"- {alias}\n"
                                
                                # 添加参考链接
                                if 'references' in osv_data and osv_data['references']:
                                    vuln_details['description'] += "\n参考链接: \n"
                                    for ref in osv_data['references']:
                                        if 'url' in ref:
                                            vuln_details['description'] += f"- {ref['url']}\n"
                                
                                # 添加受影响版本范围
                                if 'affected' in osv_data and osv_data['affected']:
                                    vuln_details['description'] += "\n影响范围: \n"
                                    for affected in osv_data['affected']:
                                        if 'package' in affected and 'name' in affected['package']:
                                            package_name = affected['package']['name']
                                            if 'ranges' in affected:
                                                for range_info in affected['ranges']:
                                                    if 'events' in range_info:
                                                        events = range_info['events']
                                                        range_str = ""
                                                        for event in events:
                                                            if 'introduced' in event:
                                                                if event['introduced'] == "0":
                                                                    range_str += "所有版本 "
                                                                else:
                                                                    range_str += f">= {event['introduced']} "
                                                            if 'fixed' in event:
                                                                range_str += f"< {event['fixed']} "
                                                            vuln_details['description'] += f"- {package_name}: {range_str}\n"
                                            elif 'versions' in affected and affected['versions']:
                                                versions = ", ".join(affected['versions'])
                                                vuln_details['description'] += f"- {package_name}: {versions}\n"
                                            else:
                                                vuln_details['description'] += f"- {package_name}: 未指定版本范围\n"
                                
                                # 提取CVE信息并增强描述
                                if 'aliases' in osv_data:
                                    cve_ids = [id for id in osv_data['aliases'] if id.startswith('CVE-')]
                                    for cve_id in cve_ids:
                                        vuln_details['description'] = self._enhance_with_cve_info(vuln_details['description'], osv_data)
                                
                                # 确定严重程度
                                if 'database_specific' in osv_data and 'severity' in osv_data['database_specific']:
                                    raw_severity = osv_data['database_specific']['severity']
                                    severity_mapping = {
                                        "CRITICAL": "严重",
                                        "HIGH": "高危",
                                        "MEDIUM": "中危",
                                        "LOW": "低危"
                                    }
                                    vuln_details['severity'] = severity_mapping.get(raw_severity, "未知")
                            
                        vulnerabilities.append(vuln_details)
        
        return vulnerabilities
    
    def _escape_html_tags(self, text: str) -> str:
        """转义HTML标签，防止XSS注入"""
        if text is None:
            return ""
        
        # 转义HTML标签
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&#39;")
        
        return text
    
    def _fetch_vuln_with_fallback(self, vuln_id: str, raw_id: str = None) -> Optional[Dict]:
        """
        获取漏洞详细信息，支持复合ID回退
        
        如果是复合ID（如"GHSA-qxp5-gwg8-xv66 / GO-2025-3503"），
        先尝试第一个ID，失败时再尝试第二个ID
        
        Args:
            vuln_id: 已清理的漏洞ID
            raw_id: 原始漏洞ID，可能包含多个ID
            
        Returns:
            Optional[Dict]: 漏洞详细信息，如果获取失败返回None
        """
        # 先尝试使用提供的ID查询
        result = self._fetch_vuln_info(vuln_id)
        if result:
            return result
        
        # 如果有原始ID且包含"/"，表示可能是复合ID
        if raw_id and "/" in raw_id:
            # 去除前缀
            clean_raw_id = self._clean_vulnerability_id(raw_id)
            
            # 分割多个ID
            ids = [id.strip() for id in clean_raw_id.split("/")]
            logger.info(f"检测到复合ID: {ids}, 正在尝试替代查询...")
            
            # 已经尝试过第一个ID（如果它与vuln_id相同），现在尝试其他ID
            for id in ids:
                if id != vuln_id:  # 避免重复查询
                    logger.info(f"尝试使用替代ID查询: {id}")
                    result = self._fetch_vuln_info(id)
                    if result:
                        return result
        
        # 所有尝试都失败
        return None
    
    def _generate_html_report(self, output_path: str) -> None:
        """生成HTML格式的报告"""
        
        # 生成HTML内容
        html_content = self._get_html_report_content()
        
        # 写入文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _get_html_report_content(self) -> str:
        """获取HTML报告内容"""
        # 定义CSS样式
        css_styles = """
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f9f9f9;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            word-wrap: break-word;
            max-width: 800px;
        }
        th {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .section-header {
            font-weight: bold;
            color: #2980b9;
            margin-top: 10px;
            display: block;
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }
        .cve-header {
            font-weight: bold;
            color: #e74c3c;
            margin-top: 15px;
            display: block;
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }
        .collapsible {
            background-color: #f2f2f2;
            color: #2980b9;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 18px;
            margin-top: 20px;
            border-radius: 5px 5px 0 0;
            border-left: 5px solid #3498db;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .active, .collapsible:hover {
            background-color: #e9ecef;
        }
        .content {
            display: none;
            overflow: hidden;
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 0 0 5px 5px;
        }
        .collapsible:after {
            content: '+';
            font-weight: bold;
            float: right;
            margin-left: 5px;
        }
        .active:after {
            content: '-';
        }
        .security-score {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .score-summary {
            text-align: center;
            margin-bottom: 20px;
        }
        .total-score {
            font-size: 36px;
            font-weight: bold;
            color: #2980b9;
        }
        .score-percentage {
            font-size: 24px;
            color: #666;
            margin: 0 10px;
        }
        .score-grade {
            display: inline-block;
            padding: 2px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-left: 10px;
            color: white;
        }
        .grade-a {
            background-color: #4CAF50;
        }
        .grade-b {
            background-color: #FFC107;
        }
        .grade-c {
            background-color: #FF9800;
        }
        .grade-d, .grade-f {
            background-color: #F44336;
        }
        .category-score {
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 5px;
        }
        .category-score-high {
            background-color: #E8F5E9;
        }
        .category-score-medium {
            background-color: #FFF8E1;
        }
        .category-score-low {
            background-color: #FFEBEE;
        }
        .vuln-critical {
            color: #d32f2f;
            font-weight: bold;
        }
        .vuln-high {
            color: #f44336;
            font-weight: bold;
        }
        .vuln-medium {
            color: #ff9800;
        }
        .vuln-low {
            color: #4caf50;
        }
        .vuln-unknown {
            color: #9e9e9e;
        }
        .vuln-link {
            word-break: break-all;
            display: block;
            padding: 3px 0;
        }
        .risk-container {
            padding: 10px 0;
        }
        .risk-high {
            background-color: #FFEAEA;
            border-left: 4px solid #F44336;
            padding: 12px 15px;
            margin: 12px 0;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(244, 67, 54, 0.1);
        }
        .risk-medium {
            background-color: #FFF8E1;
            border-left: 4px solid #FFC107;
            padding: 12px 15px;
            margin: 12px 0;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(255, 193, 7, 0.1);
        }
        .risk-low {
            background-color: #E8F5E9;
            border-left: 4px solid #4CAF50;
            padding: 12px 15px;
            margin: 12px 0;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(76, 175, 80, 0.1);
        }
        .stage-header {
            background-color: #EFF8FF;
            padding: 12px 15px;
            margin: 25px 0 15px 0;
            border-radius: 4px;
            border-bottom: 2px solid #2196F3;
            color: #1976D2;
            font-weight: bold;
            font-size: 17px;
            box-shadow: 0 2px 4px rgba(33, 150, 243, 0.1);
        }
        .risk-category {
            color: #333;
            font-weight: bold;
            font-size: 17px;
            margin-bottom: 10px;
            border-bottom: 1px solid rgba(0,0,0,0.05);
            padding-bottom: 5px;
        }
        .risk-description {
            margin-bottom: 10px;
            line-height: 1.6;
            font-size: 15px;
        }
        .risk-affected {
            font-size: 14px;
            margin-bottom: 10px;
            padding: 5px;
            background-color: rgba(255,255,255,0.5);
            border-radius: 3px;
        }
        .risk-recommendation {
            font-style: italic;
            background-color: rgba(255, 255, 255, 0.7);
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            box-shadow: inset 0 0 5px rgba(0,0,0,0.05);
            border: 1px solid rgba(0,0,0,0.05);
        }
        /* 版本降级警告样式 */
        .warning-box {
            background-color: #ffebee;
            border: 2px solid #f44336;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            box-shadow: 0 2px 8px rgba(244, 67, 54, 0.2);
        }
        .warning-title {
            color: #d32f2f;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
            border-bottom: 1px solid #ffcdd2;
            padding-bottom: 5px;
        }
        .warning-content {
            color: #b71c1c;
        }
        .warning-note {
            font-weight: bold;
            color: #c62828;
            margin-top: 10px;
            font-style: italic;
        }
        .critical-detail {
            color: #d32f2f;
            font-weight: bold;
            background-color: #ffebee;
            padding: 3px 5px;
            border-radius: 3px;
        }
        .details-list {
            margin: 5px 0;
            padding-left: 20px;
        }
        .impact-factors {
            margin-top: 8px;
            font-size: 0.9em;
            color: #555;
        }
        .score {
            padding: 2px 10px;
            border-radius: 15px;
            font-weight: bold;
            color: white;
        }
        .score-high {
            background-color: #4CAF50;
        }
        .score-medium {
            background-color: #FFC107;
        }
        .score-low {
            background-color: #F44336;
        }
        """

        # 简单的HTML模板
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>SBOM 比较报告</title>
            <style>
                {css_styles}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>SBOM 比较报告</h1>
                <p>生成时间: {timestamp}</p>
                <p>SBOM A: {sbom_a_path}</p>
                <p>SBOM B: {sbom_b_path}</p>
                
                <h2>基本统计信息</h2>
                <table>
                    <tr>
                        <th>新增包数量</th>
                        <td>{added_count}</td>
                    </tr>
                    <tr>
                        <th>移除包数量</th>
                        <td>{removed_count}</td>
                    </tr>
                    <tr>
                        <th>版本变更数量</th>
                        <td>{version_changes_count}</td>
                    </tr>
                    <tr>
                        <th>许可证变更数量</th>
                        <td>{license_changes_count}</td>
                    </tr>
                </table>
                
                {security_score_section}
                {vulnerability_section}
                {added_packages_section}
                {removed_packages_section}
                {version_changes_section}
                {license_changes_section}
                {supplier_changes_section}
                {dependency_graph_section}
                {risk_analysis_section}
                {added_pkg_vulnerabilities_section}
                {version_changed_vulnerabilities_section}
                {file_stats}
                {added_files_section}
                {removed_files_section}
                {file_changes_section}
            </div>
            
            <script>
                // 初始化所有content的样式为隐藏
                document.addEventListener('DOMContentLoaded', function() {{
                    var contents = document.querySelectorAll('.content');
                    for (var i = 0; i < contents.length; i++) {{
                        contents[i].style.display = "none";
                    }}
                }});
                
                var coll = document.getElementsByClassName("collapsible");
                for (var i = 0; i < coll.length; i++) {{
                    coll[i].addEventListener("click", function(e) {{
                        // 阻止按钮的默认行为，防止页面刷新
                        e.preventDefault();
                        this.classList.toggle("active");
                        var content = this.nextElementSibling;
                        if (content.style.display === "block") {{
                            content.style.display = "none";
                        }} else {{
                            content.style.display = "block";
                        }}
                    }});
                }}
            </script>
        </body>
        </html>
        """

        # 新增包部分 - 改为可收缩
        added_packages_section = ""
        if self.result.added_packages:
            rows = []
            for pkg_name in self.result.added_packages:
                pkg = self.sbom_b.get_package_by_name(pkg_name)
                version = pkg.version if pkg and pkg.version else "未知"
                license_name = pkg.license_concluded if pkg and pkg.license_concluded else "未知"
                rows.append(f"<tr><td>{pkg_name}</td><td>{version}</td><td>{license_name}</td></tr>")
            
            added_packages_section = f"""
            <button type="button" class="collapsible">
                <span style="flex-grow: 1;">新增包 ({len(self.result.added_packages)})</span>
                <span style="font-size:14px;color:#666">点击展开/收起</span>
            </button>
            <div class="content">
                <table>
                    <tr>
                        <th>包名</th>
                        <th>版本</th>
                        <th>许可证</th>
                    </tr>
                    {"".join(rows)}
                </table>
            </div>
            """

        # 移除包部分 - 改为可收缩
        removed_packages_section = ""
        if self.result.removed_packages:
            rows = []
            for pkg_name in self.result.removed_packages:
                pkg = self.sbom_a.get_package_by_name(pkg_name)
                version = pkg.version if pkg and pkg.version else "未知"
                license_name = pkg.license_concluded if pkg and pkg.license_concluded else "未知"
                rows.append(f"<tr><td>{pkg_name}</td><td>{version}</td><td>{license_name}</td></tr>")
            
            removed_packages_section = f"""
            <button type="button" class="collapsible">
                <span style="flex-grow: 1;">移除包 ({len(self.result.removed_packages)})</span>
                <span style="font-size:14px;color:#666">点击展开/收起</span>
            </button>
            <div class="content">
                <table>
                    <tr>
                        <th>包名</th>
                        <th>版本</th>
                        <th>许可证</th>
                    </tr>
                    {"".join(rows)}
                </table>
            </div>
            """
        
        # 版本变更部分
        version_changes_section = ""
        if self.result.version_changes:
            rows = []
            # 检测版本降级
            downgrades = []
            
            for change in self.result.version_changes:
                # 规范化版本号进行比较
                normalized_old = self._normalize_version(change.old_version)
                normalized_new = self._normalize_version(change.new_version)
                
                # 当规范化后的版本相同时显示为"无变更"
                row_class = ""
                if normalized_old == normalized_new:
                    change_type = "无变更"
                else:
                    # 检查是否为降级
                    is_downgrade = False
                    try:
                        old_parts = [int(p.split('-')[0]) for p in normalized_old.split('.')]
                        new_parts = [int(p.split('-')[0]) for p in normalized_new.split('.')]
                        
                        for i in range(min(len(old_parts), len(new_parts))):
                            if new_parts[i] < old_parts[i]:
                                is_downgrade = True
                                downgrades.append(change.package_name)
                                break
                            elif new_parts[i] > old_parts[i]:
                                break
                    except (ValueError, IndexError):
                        pass
                    
                    if is_downgrade:
                        change_type = "⚠️ 版本降级"
                        row_class = " class='risk-high'"
                    else:
                        change_type = "主版本" if change.is_major else "次版本" if change.is_minor else "补丁版本" if change.is_patch else "一般变更"
                        row_class = ""
                
                rows.append(f"<tr{row_class}><td>{change.package_name}</td><td>{change.old_version}</td><td>{change.new_version}</td><td>{change_type}</td></tr>")
            
            downgrade_warning = ""
            if downgrades:
                downgrade_warning = f"""
                <div class="downgrade-warning">
                    <p>⚠️ <strong>警告</strong>: 检测到{len(downgrades)}个包发生版本降级，可能丢失安全修复或引入兼容性问题:</p>
                    <ul>
                        {"".join([f"<li>{pkg}</li>" for pkg in downgrades])}
                    </ul>
                </div>
                """
            
            version_changes_section = f"""
            <button type="button" class="collapsible">
                <span style="flex-grow: 1;">版本变更 ({len(self.result.version_changes)})</span>
                <span style="font-size:14px;color:#666">点击展开/收起</span>
            </button>
            <div class="content">
                <table>
                    <tr>
                        <th>包名</th>
                        <th>旧版本</th>
                        <th>新版本</th>
                        <th>变更类型</th>
                    </tr>
                    {"".join(rows)}
                </table>
                {downgrade_warning}
            </div>
            """

        # 许可证变更部分
        license_changes_section = ""
        if self.result.license_changes:
            rows = []
            for change in self.result.license_changes:
                compatibility = "是" if change.compatibility_issue else "否"
                row_class = " class='risk-high'" if change.compatibility_issue else ""
                rows.append(f"<tr{row_class}><td>{change.package_name}</td><td>{change.old_license}</td><td>{change.new_license}</td><td>{compatibility}</td></tr>")
            
            license_changes_section = f"""
            <button type="button" class="collapsible">
                <span style="flex-grow: 1;">许可证变更 ({len(self.result.license_changes)})</span>
                <span style="font-size:14px;color:#666">点击展开/收起</span>
            </button>
            <div class="content">
                <table>
                    <tr>
                        <th>包名</th>
                        <th>旧许可证</th>
                        <th>新许可证</th>
                        <th>兼容性问题</th>
                    </tr>
                    {"".join(rows)}
                </table>
            </div>
            """
        
        # 生成供应商变更部分
        supplier_changes_section = ""
        if self.result.supplier_changes:
            rows = []
            for change in self.result.supplier_changes:
                rows.append(f"""
                <tr>
                    <td>{change.package_name}</td>
                    <td>{change.old_supplier}</td>
                    <td>{change.new_supplier}</td>
                </tr>
                """)
            
            supplier_changes_section = f"""
            <button type="button" class="collapsible">
                <span style="flex-grow: 1;">供应商变更 ({len(self.result.supplier_changes)})</span>
                <span style="font-size:14px;color:#666">点击展开/收起</span>
            </button>
            <div class="content">
                <table>
                    <thead>
                        <tr>
                            <th>包名</th>
                            <th>旧供应商</th>
                            <th>新供应商</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rows)}
                    </tbody>
                </table>
            </div>
            """
        
        # 依赖关系图部分
        dependency_graph_section = ""
        if self.result.dependency_changes and os.path.exists(os.path.join(os.path.dirname(self.sbom_a.file_path), "dependency_graph.png")):
            dependency_graph_section = """
            <h2>依赖关系变更</h2>
            <div class="graph-container">
                <img src="dependency_graph.png" alt="Dependency Graph" style="max-width: 100%;">
            </div>
            """
        
        # 风险分析部分
        risk_analysis_section = ""
        if hasattr(self.result, "risks"):
            risk_items = []
            
            # 收集所有风险，按阶段和级别进行分组
            all_stages = {"source": [], "ci": [], "container": [], "end-to-end": [], None: []}
            
            risk_levels = ["high", "medium", "low"]
            for level in risk_levels:
                if level in self.result.risks and self.result.risks[level]:
                    # 按供应链阶段分组
                    stage_risks = self._group_risks_by_stage(self.result.risks[level])
                    
                    # 将风险按阶段收集，并保留级别信息
                    for stage, risks in stage_risks.items():
                        if stage in all_stages:
                            for risk in risks:
                                all_stages[stage].append((level, risk))
            
            # 计算总风险数量
            total_risks = sum(len(risks) for risks in all_stages.values())
            
            # 先处理通用风险（没有特定阶段）
            if all_stages[None]:
                # 添加通用风险标题
                risk_items.append(f"""
                <div class="stage-header">
                    <span>【通用风险】</span>
                </div>
                """)
                
                # 按风险级别排序（高到低）
                general_risks = sorted(all_stages[None], key=lambda x: 
                                    0 if x[0] == "high" else 
                                    1 if x[0] == "medium" else 2)
                
                for level, risk in general_risks:
                    # 生成受影响的包列表
                    affected_packages = ""
                    if risk.affected_packages:
                        # 最多显示5个包
                        display_packages = risk.affected_packages[:5]
                        affected_packages = ", ".join(display_packages)
                        
                        # 如果超过5个，显示总数
                        if len(risk.affected_packages) > 5:
                            affected_packages += f"... 等共{len(risk.affected_packages)}个包"
                    
                    risk_items.append(f"""
                    <div class="risk-{level}">
                        <div class="risk-category">{risk.category}</div>
                        <div class="risk-description">{risk.description}</div>
                        <div class="risk-affected"><strong>受影响的包:</strong> {affected_packages}</div>
                        <div class="risk-recommendation"><strong>建议:</strong> {risk.recommendation}</div>
                    </div>
                    """)
            
            # 处理按阶段分组的风险
            stages = ["source", "ci", "container", "end-to-end"]
            for stage in stages:
                if all_stages[stage]:  # 如果该阶段有风险
                    stage_name = self._get_stage_name(stage)
                    # 只添加一次阶段标题
                    risk_items.append(f"""
                    <div class="stage-header">
                        <span>【{stage_name}阶段】</span>
                    </div>
                    """)
                    
                    # 按风险级别排序（高到低）
                    stage_risks = sorted(all_stages[stage], key=lambda x: 
                                        0 if x[0] == "high" else 
                                        1 if x[0] == "medium" else 2)
                    
                    for level, risk in stage_risks:
                        # 生成受影响的包列表
                        affected_packages = ""
                        if risk.affected_packages:
                            # 最多显示5个包
                            display_packages = risk.affected_packages[:5]
                            affected_packages = ", ".join(display_packages)
                            
                            # 如果超过5个，显示总数
                            if len(risk.affected_packages) > 5:
                                affected_packages += f"... 等共{len(risk.affected_packages)}个包"
                        
                        risk_items.append(f"""
                        <div class="risk-{level}">
                            <div class="risk-category">{risk.category}</div>
                            <div class="risk-description">{risk.description}</div>
                            <div class="risk-affected"><strong>受影响的包:</strong> {affected_packages}</div>
                            <div class="risk-recommendation"><strong>建议:</strong> {risk.recommendation}</div>
                        </div>
                        """)
        
        # 安全评分部分
        security_score_section = ""
        if hasattr(self.result, "security_score"):
            security_score = self.result.security_score
            percentage = (security_score.total_score / security_score.max_score) * 100
            
            # 根据得分确定颜色
            if percentage >= 80:
                score_color = "score-high"
            elif percentage >= 60:
                score_color = "score-medium"
            else:
                score_color = "score-low"
            
            # 版本降级警告区域
            downgrade_warning = ""
            critical_details = []
            
            # 检查是否有版本降级
            if "version_consistency" in security_score.categories:
                vc_category = security_score.categories["version_consistency"]
                for detail in vc_category.details:
                    if "降级" in detail:
                        critical_details.append(detail)
            
            # 如果有版本降级，添加警告区域
            if critical_details:
                downgrade_warning = f"""
                <div class="warning-box">
                    <div class="warning-title">⚠️ 版本降级警告</div>
                    <div class="warning-content">
                        <ul>
                            {"".join(f"<li>{detail}</li>" for detail in critical_details)}
                        </ul>
                        <p class="warning-note">版本降级可能导致安全修复丢失，增加安全风险！</p>
                    </div>
                </div>
                """
            
            # 生成各类别得分表格
            category_rows = []
            for category_name, category in security_score.categories.items():
                cat_percentage = (category.score / category.max_score) * 100
                
                # 根据类别得分确定颜色
                if cat_percentage >= 80:
                    cat_score_class = "score-high"
                elif cat_percentage >= 60:
                    cat_score_class = "score-medium"
                else:
                    cat_score_class = "score-low"
                
                # 创建详细信息HTML
                details_html = ""
                if category.details:
                    details_html = "<ul class='details-list'>"
                    for detail in category.details:
                        # 检查是否为降级或高危提示，添加特殊样式
                        if "降级" in detail or "高危" in detail or "严重" in detail:
                            details_html += f"<li class='critical-detail'>{detail}</li>"
                        else:
                            details_html += f"<li>{detail}</li>"
                    details_html += "</ul>"
                
                # 创建影响因素HTML
                impact_html = ""
                if category.impact_factors:
                    impact_html = "<div class='impact-factors'><strong>影响因素:</strong> "
                    impact_html += ", ".join(category.impact_factors)
                    impact_html += "</div>"
                
                # 添加到表格行
                category_rows.append(f"""
                <tr>
                    <td>{category.name}</td>
                    <td class="{cat_score_class}">{category.score:.1f}/{category.max_score:.1f} ({cat_percentage:.1f}%)</td>
                    <td>{details_html}{impact_html}</td>
                </tr>
                """)
            
            # 构建安全评分部分
            security_score_section = f"""
            <button type="button" class="collapsible">
                <span style="flex-grow: 1;">软件供应链安全评分</span>
                <span class="score {score_color}">{security_score.total_score:.1f}/10 ({percentage:.1f}%) [{security_score.grade}]</span>
            </button>
            <div class="content">
                {downgrade_warning}
                <p class="score-summary">{security_score.summary}</p>
                <table>
                    <thead>
                        <tr>
                            <th>类别</th>
                            <th>得分</th>
                            <th>详情</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(category_rows)}
                    </tbody>
                </table>
            </div>
            """
        
        # 添加漏洞信息部分
        vulnerability_section = ""
        if hasattr(self.result, "security_score"):
            security_score = self.result.security_score
            scorecard_category = security_score.categories.get("scorecard_assessment")
            if scorecard_category:
                vulnerabilities = self._process_vulnerabilities(scorecard_category)
                
                if vulnerabilities:
                    # 按严重程度排序
                    severity_order = {"严重": 1, "高危": 2, "中危": 3, "低危": 4, "未知": 5}
                    vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 5))
                    
                    # 生成漏洞表格HTML
                    vuln_rows = []
                    for vuln in vulnerabilities:
                        severity_class = {
                            "严重": "vuln-critical",
                            "高危": "vuln-high",
                            "中危": "vuln-medium",
                            "低危": "vuln-low",
                            "未知": "vuln-unknown"
                        }.get(vuln["severity"], "vuln-unknown")
                        
                        # 预处理描述文本，将换行符替换为HTML标签
                        description_lines = vuln['description'].split('\n')
                        processed_lines = []
                        current_section = []
                        
                        for line in description_lines:
                            # 确保行内容被转义
                            line = self._escape_html_tags(line)
                            
                            if line.startswith("相关漏洞ID:") or line.startswith("参考链接:") or line.startswith("影响范围:"):
                                if current_section:
                                    processed_lines.append('<br>'.join(current_section))
                                    current_section = []
                                processed_lines.append(f'<div class="section-header">{line}</div>')
                            elif line.startswith("来自 CVE-") and "的附加信息:" in line:
                                if current_section:
                                    processed_lines.append('<br>'.join(current_section))
                                    current_section = []
                                processed_lines.append(f'<div class="cve-header">{line}</div>')
                            elif line.startswith("描述:") or line.startswith("发布日期:") or line.startswith("最后更新:") or line.startswith("CVE参考链接:"):
                                if current_section:
                                    processed_lines.append('<br>'.join(current_section))
                                    current_section = []
                                processed_lines.append(f'<div class="section-header">{line}</div>')
                            elif line.startswith("- "):
                                if "://" in line:  # 这是一个URL链接
                                    url = self._escape_html_tags(line[2:])
                                    current_section.append(f'<span class="vuln-link">{url}</span>')
                                else:
                                    current_section.append(line[2:])
                            else:
                                if current_section:
                                    processed_lines.append('<br>'.join(current_section))
                                    current_section = []
                                processed_lines.append(line)
                        
                        if current_section:
                            processed_lines.append('<br>'.join(current_section))
                        
                        description_html = '<br>'.join(processed_lines)
                        
                        vuln_rows.append(f"""
                        <tr>
                            <td>{self._escape_html_tags(vuln['id'])}</td>
                            <td>{description_html}</td>
                        </tr>
                        """)
                    
                    vulnerability_section = f"""
                    <button type="button" class="collapsible">
                        <span style="flex-grow: 1;">漏洞信息（来源：OSV） ({len(vulnerabilities)})</span>
                        <span style="font-size:14px;color:#666">点击展开/收起</span>
                    </button>
                    <div class="content">
                        <table>
                            <thead>
                                <tr>
                                    <th style="width: 25%">漏洞ID</th>
                                    <th style="width: 75%">描述</th>
                                </tr>
                            </thead>
                            <tbody>
                                {"".join(vuln_rows)}
                            </tbody>
                        </table>
                    </div>
                    """
        
        # 添加新增包漏洞信息部分
        added_pkg_vulnerabilities_section = ""
        if self.result.added_packages:
            # 获取新增包的漏洞信息
            pkg_vulns = self._fetch_package_vulnerabilities_batch(self.result.added_packages)
            
            if pkg_vulns:
                # 计算总漏洞数
                total_vulns = sum(len(vulns) for vulns in pkg_vulns.values())
                
                # 生成漏洞表格
                vuln_rows = []
                
                # 按包名处理所有漏洞
                for pkg_name, vulns in pkg_vulns.items():
                    for vuln in vulns:
                        vuln_id = vuln["id"]
                        
                        # 初始化所有字段
                        severity = "未知"
                        description = vuln.get("summary", "")
                        affected_versions = ""
                        published_date = ""
                        cve_ids = []
                        references = []
                        
                        # 提取严重程度
                        if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                            raw_severity = vuln["database_specific"]["severity"]
                            severity_map = {
                                "CRITICAL": "严重",
                                "HIGH": "高危",
                                "MEDIUM": "中危",
                                "LOW": "低危"
                            }
                            severity = severity_map.get(raw_severity, "未知")
                        
                        # 提取详细描述
                        if "details" in vuln:
                            description = f"{description}<br><br>{vuln['details']}"
                        
                        # 提取发布日期
                        if "published" in vuln:
                            try:
                                published_date = vuln["published"][:10]  # 获取年月日部分
                            except:
                                published_date = ""
                        
                        # 提取相关CVE ID
                        if "aliases" in vuln:
                            cve_ids = [cve for cve in vuln["aliases"] if cve.startswith("CVE-")]
                        
                        # 提取受影响的版本范围
                        if "affected" in vuln:
                            version_ranges = []
                            for affected in vuln["affected"]:
                                if "package" in affected and affected["package"].get("name") == pkg_name.split('@')[0]:
                                    # 检查版本范围
                                    if "ranges" in affected:
                                        for range_info in affected["ranges"]:
                                            if range_info.get("type") == "SEMVER" and "events" in range_info:
                                                events = range_info["events"]
                                                range_desc = []
                                                
                                                for event in events:
                                                    if "introduced" in event:
                                                        if event["introduced"] == "0":
                                                            range_desc.append("所有版本")
                                                        else:
                                                            range_desc.append(f">= {event['introduced']}")
                                                    if "fixed" in event:
                                                        range_desc.append(f"< {event['fixed']}")
                                                
                                                if range_desc:
                                                    version_ranges.append(" ".join(range_desc))
                            
                                    # 直接使用受影响的版本列表
                                    if "versions" in affected and affected["versions"]:
                                        version_ranges.append(f"具体受影响版本: {', '.join(affected['versions'])}")
                        
                        if version_ranges:
                            affected_versions = "<br>".join(version_ranges)
                        else:
                            affected_versions = "未指定"
                        
                        # 获取参考链接
                        if "references" in vuln:
                            for ref in vuln["references"][:5]:  # 最多显示5个链接
                                if "url" in ref:
                                    references.append(ref["url"])
                        
                        # 使用适当的严重等级样式
                        severity_class = {
                            "严重": "vuln-critical",
                            "高危": "vuln-high",
                            "中危": "vuln-medium",
                            "低危": "vuln-low",
                            "未知": "vuln-unknown"
                        }.get(severity, "vuln-unknown")
                        
                        # 添加CVE信息
                        cve_info = f"关联CVE: {', '.join(cve_ids)}" if cve_ids else ""
                        
                        # 构建参考链接HTML
                        refs_html = ""
                        if references:
                            refs_html = "<div class='vuln-refs'><strong>参考链接:</strong><br>" + "<br>".join([f"<a href='{self._escape_html_tags(url)}' target='_blank' class='vuln-link'>{self._escape_html_tags(url)}</a>" for url in references]) + "</div>"
                        
                        vuln_rows.append(f"""
                        <tr>
                            <td>{self._escape_html_tags(pkg_name)}</td>
                            <td class="{severity_class}">{self._escape_html_tags(vuln_id)}<br>{self._escape_html_tags(cve_info)}</td>
                            <td>{self._escape_html_tags(affected_versions)}</td>
                            <td>{self._escape_html_tags(description)}{refs_html}</td>
                            <td>{self._escape_html_tags(published_date)}</td>
                        </tr>
                        """)
                
                # 创建表格
                if vuln_rows:
                    added_pkg_vulnerabilities_section = f"""
                    <button type="button" class="collapsible">
                        <span style="flex-grow: 1;">新增包漏洞信息 ({total_vulns})</span>
                        <span style="font-size:14px;color:#666">点击展开/收起</span>
                    </button>
                    <div class="content">
                        <table>
                            <thead>
                                <tr>
                                    <th>包名</th>
                                    <th>漏洞ID</th>
                                    <th>影响版本</th>
                                    <th>描述</th>
                                    <th>发布日期</th>
                                </tr>
                            </thead>
                            <tbody>
                                {"".join(vuln_rows)}
                            </tbody>
                        </table>
                    </div>
                    """
        
        # 添加版本变更包漏洞信息部分
        version_changed_vulnerabilities_section = ""
        if self.result.version_changes:
            # 获取版本变更包的漏洞信息
            version_changed_vulnerabilities = self._check_version_changed_vulnerabilities()
            
            if version_changed_vulnerabilities:
                # 计算总漏洞数
                total_vulns = sum(len(vulns) for vulns in version_changed_vulnerabilities.values())
                
                # 生成漏洞表格
                vuln_rows = []
                
                # 按包名处理所有漏洞
                for pkg_name, vulns in version_changed_vulnerabilities.items():
                    for vuln in vulns:
                        vuln_id = vuln["id"]
                        
                        # 初始化所有字段
                        severity = "未知"
                        description = vuln.get("summary", "")
                        affected_versions = ""
                        published_date = ""
                        cve_ids = []
                        references = []
                        
                        # 提取严重程度
                        if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                            raw_severity = vuln["database_specific"]["severity"]
                            severity_map = {
                                "CRITICAL": "严重",
                                "HIGH": "高危",
                                "MEDIUM": "中危",
                                "LOW": "低危"
                            }
                            severity = severity_map.get(raw_severity, "未知")
                        
                        # 提取详细描述
                        if "details" in vuln:
                            description = f"{description}<br><br>{vuln['details']}"
                        
                        # 提取发布日期
                        if "published" in vuln:
                            try:
                                published_date = vuln["published"][:10]  # 获取年月日部分
                            except:
                                published_date = ""
                        
                        # 提取相关CVE ID
                        if "aliases" in vuln:
                            cve_ids = [cve for cve in vuln["aliases"] if cve.startswith("CVE-")]
                        
                        # 提取受影响的版本范围
                        if "affected" in vuln:
                            version_ranges = []
                            for affected in vuln["affected"]:
                                if "package" in affected and affected["package"].get("name") == pkg_name.split('@')[0]:
                                    # 检查版本范围
                                    if "ranges" in affected:
                                        for range_info in affected["ranges"]:
                                            if range_info.get("type") == "SEMVER" and "events" in range_info:
                                                events = range_info["events"]
                                                range_desc = []
                                                
                                                for event in events:
                                                    if "introduced" in event:
                                                        if event["introduced"] == "0":
                                                            range_desc.append("所有版本")
                                                        else:
                                                            range_desc.append(f">= {event['introduced']}")
                                                    if "fixed" in event:
                                                        range_desc.append(f"< {event['fixed']}")
                                                
                                                if range_desc:
                                                    version_ranges.append(" ".join(range_desc))
                            
                                    # 直接使用受影响的版本列表
                                    if "versions" in affected and affected["versions"]:
                                        version_ranges.append(f"具体受影响版本: {', '.join(affected['versions'])}")
                        
                        if version_ranges:
                            affected_versions = "<br>".join(version_ranges)
                        else:
                            affected_versions = "未指定"
                        
                        # 获取参考链接
                        if "references" in vuln:
                            for ref in vuln["references"][:5]:  # 最多显示5个链接
                                if "url" in ref:
                                    references.append(ref["url"])
                        
                        # 使用适当的严重等级样式
                        severity_class = {
                            "严重": "vuln-critical",
                            "高危": "vuln-high",
                            "中危": "vuln-medium",
                            "低危": "vuln-low",
                            "未知": "vuln-unknown"
                        }.get(severity, "vuln-unknown")
                        
                        # 添加CVE信息
                        cve_info = f"关联CVE: {', '.join(cve_ids)}" if cve_ids else ""
                        
                        # 构建参考链接HTML
                        refs_html = ""
                        if references:
                            refs_html = "<div class='vuln-refs'><strong>参考链接:</strong><br>" + "<br>".join([f"<a href='{self._escape_html_tags(url)}' target='_blank' class='vuln-link'>{self._escape_html_tags(url)}</a>" for url in references]) + "</div>"
                        
                        vuln_rows.append(f"""
                        <tr>
                            <td>{self._escape_html_tags(pkg_name)}</td>
                            <td class="{severity_class}">{self._escape_html_tags(vuln_id)}<br>{self._escape_html_tags(cve_info)}</td>
                            <td>{self._escape_html_tags(affected_versions)}</td>
                            <td>{self._escape_html_tags(description)}{refs_html}</td>
                            <td>{self._escape_html_tags(published_date)}</td>
                        </tr>
                        """)
                
                # 创建表格
                if vuln_rows:
                    version_changed_vulnerabilities_section = f"""
                    <button type="button" class="collapsible">
                        <span style="flex-grow: 1;">版本变更引入的漏洞 ({total_vulns})</span>
                        <span style="font-size:14px;color:#666">点击展开/收起</span>
                    </button>
                    <div class="content">
                        <table>
                            <thead>
                                <tr>
                                    <th>包名</th>
                                    <th>漏洞ID</th>
                                    <th>影响版本</th>
                                    <th>描述</th>
                                    <th>发布日期</th>
                                </tr>
                            </thead>
                            <tbody>
                                {"".join(vuln_rows)}
                            </tbody>
                        </table>
                    </div>
                    """
        
        # 文件统计部分
        file_stats = ""
        added_files_section = ""
        removed_files_section = ""
        file_changes_section = ""
        
        if hasattr(self.result, "file_changes"):
            # 文件统计信息
            file_stats = f"""
            <h3>文件统计</h3>
            <table>
                <tr>
                    <th>总文件数 (SBOM A)</th>
                    <td>{len(self.sbom_a.files) if hasattr(self.sbom_a, 'files') else 0}</td>
                </tr>
                <tr>
                    <th>总文件数 (SBOM B)</th>
                    <td>{len(self.sbom_b.files) if hasattr(self.sbom_b, 'files') else 0}</td>
                </tr>
                <tr>
                    <th>新增文件数</th>
                    <td>{len(self.result.added_files)}</td>
                </tr>
                <tr>
                    <th>移除文件数</th>
                    <td>{len(self.result.removed_files)}</td>
                </tr>
                <tr>
                    <th>文件内容变更数</th>
                    <td>{len(self.result.file_changes)}</td>
                </tr>
            </table>
            """
            
            # 新增文件部分
            if self.result.added_files:
                display_files = self.result.added_files[:100]  # 最多显示100个文件
                has_more = len(self.result.added_files) > 100
                
                rows = []
                for file_name in display_files:
                    rows.append(f"<tr><td>{file_name}</td></tr>")
                
                show_more_text = f"(仅显示前100个，共{len(self.result.added_files)}个)" if has_more else ""
                
                added_files_section = f"""
                <button type="button" class="collapsible">
                    <span style="flex-grow: 1;">新增文件 ({len(self.result.added_files)})</span>
                    <span style="font-size:14px;color:#666">点击展开/收起</span>
                </button>
                <div class="content">
                    <p>{show_more_text}</p>
                    <table>
                        <tr>
                            <th>文件名</th>
                        </tr>
                        {"".join(rows)}
                    </table>
                </div>
                """
            
            # 移除文件部分
            if self.result.removed_files:
                display_files = self.result.removed_files[:100]  # 最多显示100个文件
                has_more = len(self.result.removed_files) > 100
                
                rows = []
                for file_name in display_files:
                    rows.append(f"<tr><td>{file_name}</td></tr>")
                
                show_more_text = f"(仅显示前100个，共{len(self.result.removed_files)}个)" if has_more else ""
                
                removed_files_section = f"""
                <button type="button" class="collapsible">
                    <span style="flex-grow: 1;">移除文件 ({len(self.result.removed_files)})</span>
                    <span style="font-size:14px;color:#666">点击展开/收起</span>
                </button>
                <div class="content">
                    <p>{show_more_text}</p>
                    <table>
                        <tr>
                            <th>文件名</th>
                        </tr>
                        {"".join(rows)}
                    </table>
                </div>
                """
            
            # 文件内容变更部分
            if self.result.file_changes:
                rows = []
                for change in self.result.file_changes:
                    change_type = "内容变更" if change.has_content_change else "校验和变更"
                    rows.append(f"<tr><td>{change.file_name}</td><td>{change_type}</td></tr>")
                
                file_changes_section = f"""
                <button type="button" class="collapsible">
                    <span style="flex-grow: 1;">文件变更 ({len(self.result.file_changes)})</span>
                    <span style="font-size:14px;color:#666">点击展开/收起</span>
                </button>
                <div class="content">
                    <table>
                        <tr>
                            <th>文件名</th>
                            <th>变更类型</th>
                        </tr>
                        {"".join(rows)}
                    </table>
                </div>
                """
        
        # 在HTML模板中添加漏洞信息部分
        html_content = html_template.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            sbom_a_path=self.sbom_a.file_path,
            sbom_b_path=self.sbom_b.file_path,
            added_count=len(self.result.added_packages),
            removed_count=len(self.result.removed_packages),
            version_changes_count=len(self.result.version_changes),
            license_changes_count=len(self.result.license_changes),
            added_packages_section=added_packages_section,
            removed_packages_section=removed_packages_section,
            version_changes_section=version_changes_section,
            license_changes_section=license_changes_section,
            supplier_changes_section=supplier_changes_section,
            dependency_graph_section=dependency_graph_section,
            risk_analysis_section=risk_analysis_section,
            security_score_section=security_score_section,
            vulnerability_section=vulnerability_section,
            added_pkg_vulnerabilities_section=added_pkg_vulnerabilities_section,
            version_changed_vulnerabilities_section=version_changed_vulnerabilities_section,
            file_stats=file_stats,
            added_files_section=added_files_section,
            removed_files_section=removed_files_section,
            file_changes_section=file_changes_section,
            css_styles=css_styles
        )
        
        return html_content
    
    def _generate_json_report(self, output_path: str) -> None:
        """生成JSON格式的报告"""
        # 构建JSON数据结构
        report_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "sbom_a": self.sbom_a.file_path,
                "sbom_b": self.sbom_b.file_path
            },
            "statistics": {
                "packages_a": len(self.sbom_a.packages),
                "packages_b": len(self.sbom_b.packages),
                "added_packages": len(self.result.added_packages),
                "removed_packages": len(self.result.removed_packages),
                "version_changes": len(self.result.version_changes),
                "license_changes": len(self.result.license_changes),
                "supplier_changes": len(self.result.supplier_changes),
                "dependency_changes": len(self.result.dependency_changes)
            },
            "added_packages": [],
            "removed_packages": [],
            "version_changes": [],
            "license_changes": [],
            "supplier_changes": [],
            "dependency_changes": []
        }
        
        # 添加安全评分
        if hasattr(self.result, "security_score"):
            security_score = self.result.security_score
            report_data["security_score"] = {
                "total_score": security_score.total_score,
                "max_score": 10.0,  # 固定为10分制
                "percentage": (security_score.total_score / security_score.max_score) * 100,
                "grade": security_score.grade,
                "summary": security_score.summary,
                "scale": "10分制",  # 添加评分制度标识
                "categories": {}
            }
            
            # 添加各分类得分
            for category_name, category in security_score.categories.items():
                report_data["security_score"]["categories"][category_name] = {
                    "name": category.name,
                    "score": category.score,
                    "max_score": category.max_score,
                    "percentage": (category.score / category.max_score) * 100,
                    "details": category.details,
                    "impact_factors": category.impact_factors
                }
        
        # 添加详细信息
        for pkg_name in self.result.added_packages:
            pkg = self.sbom_b.get_package_by_name(pkg_name)
            report_data["added_packages"].append({
                "name": pkg_name,
                "version": pkg.version if pkg and pkg.version else None,
                "license": pkg.license_concluded if pkg and pkg.license_concluded else None
            })
        
        for pkg_name in self.result.removed_packages:
            pkg = self.sbom_a.get_package_by_name(pkg_name)
            report_data["removed_packages"].append({
                "name": pkg_name,
                "version": pkg.version if pkg and pkg.version else None,
                "license": pkg.license_concluded if pkg and pkg.license_concluded else None
            })
        
        for change in self.result.version_changes:
            # 检查是否为降级
            is_downgrade = False
            try:
                normalized_old = self._normalize_version(change.old_version)
                normalized_new = self._normalize_version(change.new_version)
                
                old_parts = [int(p.split('-')[0]) for p in normalized_old.split('.')]
                new_parts = [int(p.split('-')[0]) for p in normalized_new.split('.')]
                
                for i in range(min(len(old_parts), len(new_parts))):
                    if new_parts[i] < old_parts[i]:
                        is_downgrade = True
                        break
                    elif new_parts[i] > old_parts[i]:
                        break
            except (ValueError, IndexError):
                pass
                
            report_data["version_changes"].append({
                "package_name": change.package_name,
                "old_version": change.old_version,
                "new_version": change.new_version,
                "is_major": change.is_major,
                "is_minor": change.is_minor,
                "is_patch": change.is_patch,
                "is_downgrade": is_downgrade
            })
        
        # 收集所有版本降级的包
        downgraded_packages = [change["package_name"] for change in report_data["version_changes"] if change.get("is_downgrade")]
        if downgraded_packages:
            report_data["downgraded_packages"] = downgraded_packages
        
        for change in self.result.license_changes:
            report_data["license_changes"].append({
                "package_name": change.package_name,
                "old_license": change.old_license,
                "new_license": change.new_license,
                "compatibility_issue": change.compatibility_issue
            })
        
        for change in self.result.supplier_changes:
            report_data["supplier_changes"].append({
                "package_name": change.package_name,
                "old_supplier": change.old_supplier,
                "new_supplier": change.new_supplier
            })
        
        for change in self.result.dependency_changes:
            report_data["dependency_changes"].append({
                "package_name": change.package_name,
                "added_dependencies": change.added_dependencies,
                "removed_dependencies": change.removed_dependencies
            })
        
        # 添加风险分析
        if hasattr(self.result, "risks"):
            report_data["risk_analysis"] = {}
            for level, risks in self.result.risks.items():
                report_data["risk_analysis"][level] = []
                for risk in risks:
                    report_data["risk_analysis"][level].append({
                        "category": risk.category,
                        "description": risk.description,
                        "affected_packages": risk.affected_packages,
                        "recommendation": risk.recommendation
                    })
        
        # 添加新增包的漏洞信息
        if self.result.added_packages:
            # 获取新增包的漏洞信息
            pkg_vulns = self._fetch_package_vulnerabilities_batch(self.result.added_packages)
            
            if pkg_vulns:
                report_data["added_packages_vulnerabilities"] = {}
                for pkg_name, vulns in pkg_vulns.items():
                    report_data["added_packages_vulnerabilities"][pkg_name] = [self._convert_vuln_to_json(vuln) for vuln in vulns]
        
        # 添加版本变更包的漏洞信息
        if self.result.version_changes:
            # 获取版本变更包的漏洞信息
            version_changed_vulnerabilities = self._check_version_changed_vulnerabilities()
            
            if version_changed_vulnerabilities:
                report_data["version_changed_vulnerabilities"] = {}
                for pkg_name, vulns in version_changed_vulnerabilities.items():
                    report_data["version_changed_vulnerabilities"][pkg_name] = [self._convert_vuln_to_json(vuln) for vuln in vulns]
        
        # 写入JSON文件
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    def _convert_vuln_to_json(self, vuln: Dict) -> Dict:
        """将漏洞信息转换为JSON友好格式"""
        result = {
            "id": vuln.get("id", ""),
            "summary": vuln.get("summary", ""),
            "details": vuln.get("details", ""),
            "severity": "unknown",
            "affected_versions": [],
            "published_date": vuln.get("published", ""),
            "cve_ids": [],
            "references": []
        }
        
        # 提取严重程度
        if "database_specific" in vuln and "severity" in vuln["database_specific"]:
            result["severity"] = vuln["database_specific"]["severity"]
        
        # 提取受影响版本
        if "affected" in vuln:
            for affected in vuln["affected"]:
                if "versions" in affected:
                    result["affected_versions"] = affected["versions"]
                    break
        
        # 提取CVE ID
        if "aliases" in vuln:
            for alias in vuln["aliases"]:
                if alias.startswith("CVE-"):
                    result["cve_ids"].append(alias)
        
        # 提取参考链接
        if "references" in vuln:
            for ref in vuln["references"]:
                if "url" in ref:
                    result["references"].append(ref["url"])
        
        return result
    
    def print_console_report(self) -> None:
        """在控制台打印简洁报告"""
        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SBOM 比较结果摘要{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}SBOM A: {self.sbom_a.file_path}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}SBOM B: {self.sbom_b.file_path}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}包数量 A: {len(self.sbom_a.packages)}, B: {len(self.sbom_b.packages)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}新增包: {len(self.result.added_packages)}{Style.RESET_ALL}")
        print(f"{Fore.RED}移除包: {len(self.result.removed_packages)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}版本变更: {len(self.result.version_changes)}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}许可证变更: {len(self.result.license_changes)}{Style.RESET_ALL}")
        
        # 显示主要风险
        if hasattr(self.result, "risks"):
            print(f"\n{Fore.RED}{'=' * 80}{Style.RESET_ALL}")
            print(f"{Fore.RED}风险分析{Style.RESET_ALL}")
            print(f"{Fore.RED}{'=' * 80}{Style.RESET_ALL}")
            
            for level in ["high", "medium", "low"]:
                if level in self.result.risks and self.result.risks[level]:
                    level_color = Fore.RED if level == "high" else Fore.YELLOW if level == "medium" else Fore.GREEN
                    print(f"\n{level_color}{level.upper()} 级别风险: {len(self.result.risks[level])}{Style.RESET_ALL}")
                    
                    for risk in self.result.risks[level]:
                        print(f"{level_color}  - {risk.category}: {risk.description}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

    def _normalize_version(self, version: str) -> str:
        """
        标准化版本号，去除前缀v等
        
        Args:
            version: 原始版本号
            
        Returns:
            str: 标准化后的版本号
        """
        if not version:
            return ""
            
        # 移除版本号中可能的前缀v
        if version.startswith('v'):
            version = version[1:]
        
        # 移除版本范围符号
        version = re.sub(r'[<>=~^]', '', version)
        
        # 移除注释部分
        if ' ' in version:
            version = version.split(' ')[0]
            
        return version.strip()
        
    def _get_project_ecosystem(self) -> str:
        """
        根据项目信息确定默认的生态系统
        
        Returns:
            str: 项目的生态系统名称
        """
        # 尝试从SBOM元数据中获取编程语言
        if hasattr(self, 'sbom_b'):
            sbom = self.sbom_b
            if hasattr(sbom, 'metadata'):
                if hasattr(sbom.metadata, 'tools'):
                    for tool in sbom.metadata.tools:
                        if hasattr(tool, 'language') and tool.language:
                            return self._map_language_to_ecosystem(tool.language)
        
        # 检查项目文件类型判断编程语言
        file_extensions = self._get_project_file_extensions()
        if 'js' in file_extensions or 'jsx' in file_extensions or 'json' in file_extensions:
            return 'npm'
        elif 'py' in file_extensions:
            return 'PyPI'
        elif 'java' in file_extensions:
            return 'Maven'
        elif 'go' in file_extensions:
            return 'Go'
        elif 'rb' in file_extensions:
            return 'RubyGems'
        elif 'rs' in file_extensions:
            return 'crates.io'
        elif 'php' in file_extensions:
            return 'Packagist'
        elif 'swift' in file_extensions:
            return 'Swift'
        elif 'cs' in file_extensions:
            return 'NuGet'
        
        # 默认返回npm作为最常见的生态系统
        logger.warning("无法确定项目生态系统，默认使用npm")
        return 'npm'
    
    def _map_language_to_ecosystem(self, language: str) -> str:
        """
        将编程语言映射到对应的包管理生态系统
        
        Args:
            language: 编程语言名称
            
        Returns:
            str: 对应的生态系统名称
        """
        language_ecosystem_map = {
            'python': 'PyPI',
            'javascript': 'npm',
            'java': 'Maven',
            'go': 'Go',
            'ruby': 'RubyGems',
            'rust': 'crates.io',
            'php': 'Packagist',
            'swift': 'Swift',
            'csharp': 'NuGet',
            'c#': 'NuGet',
            'typescript': 'npm'
        }
        
        return language_ecosystem_map.get(language.lower(), 'npm')
    
    def _get_project_file_extensions(self) -> Set[str]:
        """
        获取项目中的文件扩展名集合
        
        Returns:
            Set[str]: 文件扩展名集合
        """
        extensions = set()
        
        # 当前目录为项目根目录
        project_dir = os.getcwd()
        
        # 扫描项目根目录下的文件
        for root, _, files in os.walk(project_dir):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext and len(ext) > 1:
                    extensions.add(ext[1:])  # 移除点号
        
        return extensions

    def _get_package_vulnerabilities(self, package_name: str, package_version: str = None, ecosystem: str = None) -> List[Dict]:
        """
        使用OSV API查询包的漏洞信息
        
        Args:
            package_name: 包名
            package_version: 包版本
            ecosystem: 包的生态系统（npm, maven, PyPI, golang等）
            
        Returns:
            List[Dict]: 漏洞信息列表
        """
        try:
            # 重试参数
            max_retries = 3
            retry_delay = 2  # 初始延迟2秒
            
            # 标准化版本号
            if package_version:
                package_version = self._normalize_version(package_version)
            
            # 确保ecosystem参数存在
            if not ecosystem:
                # 尝试从SBOM中获取包信息
                pkg_obj = None
                if hasattr(self, 'sbom_b'):
                    pkg_obj = self.sbom_b.get_package_by_name(package_name)
                
                if pkg_obj:
                    # 检查downloadLocation字段
                    download_location = None
                    if hasattr(pkg_obj, "download_location"):
                        download_location = pkg_obj.download_location
                    elif hasattr(pkg_obj, "downloadLocation"):
                        download_location = pkg_obj.downloadLocation
                    
                    # 使用downloadLocation判断平台
                    if download_location:
                        download_url = str(download_location).lower()
                        
                        # 判断平台
                        if "npmjs.com" in download_url or "npm.js" in download_url or "npm/package" in download_url:
                            ecosystem = "npm"
                            # logger.info(f"通过downloadLocation识别包 {package_name} 为npm包")
                        elif "pypi.org" in download_url or "python.org" in download_url:
                            ecosystem = "PyPI"
                            # logger.info(f"通过downloadLocation识别包 {package_name} 为PyPI包")
                        elif "maven" in download_url or "mvnrepository" in download_url:
                            ecosystem = "Maven"
                            # logger.info(f"通过downloadLocation识别包 {package_name} 为Maven包")
                        elif "golang.org" in download_url or "go.dev" in download_url or "go-lang" in download_url:
                            ecosystem = "Go"
                            # logger.info(f"通过downloadLocation识别包 {package_name} 为Go包")
                        elif "rubygems" in download_url or "ruby-lang" in download_url:
                            ecosystem = "RubyGems"
                            # logger.info(f"通过downloadLocation识别包 {package_name} 为RubyGems包")
                        elif "crates.io" in download_url or "rust-lang" in download_url:
                            ecosystem = "crates.io"
                            # logger.info(f"通过downloadLocation识别包 {package_name} 为Rust包")
                        elif "packagist" in download_url or "composer" in download_url:
                            ecosystem = "Packagist"
                            # logger.info(f"通过downloadLocation识别包 {package_name} 为PHP包")
                        elif "nuget" in download_url:
                            ecosystem = "NuGet"
                            # logger.info(f"通过downloadLocation识别包 {package_name} 为.NET包")
                    
                    # 从purl字段判断
                    if not ecosystem and hasattr(pkg_obj, "purl") and pkg_obj.purl:
                        purl = str(pkg_obj.purl).lower()
                        if "pkg:npm" in purl:
                            ecosystem = "npm"
                            logger.info(f"通过purl识别包 {package_name} 为npm包: {purl}")
                        elif "pkg:pypi" in purl:
                            ecosystem = "PyPI"
                            logger.info(f"通过purl识别包 {package_name} 为PyPI包: {purl}")
                        elif "pkg:maven" in purl:
                            ecosystem = "Maven"
                            logger.info(f"通过purl识别包 {package_name} 为Maven包: {purl}")
                        elif "pkg:golang" in purl:
                            ecosystem = "Go"
                            logger.info(f"通过purl识别包 {package_name} 为Go包: {purl}")
            
                # 检查特定格式
                if not ecosystem:
                    if '@' in package_name:  # npm格式: name@version
                        ecosystem = 'npm'
                        logger.info(f"通过@符号识别包 {package_name} 为npm包")
                    elif ':' in package_name:  # Maven或其他格式
                        parts = package_name.split(':')
                        if len(parts) == 3:  # groupId:artifactId:version
                            ecosystem = 'Maven'
                            logger.info(f"通过冒号格式识别包 {package_name} 为Maven包")
                    
                # 如果还没确定生态系统，使用默认生态系统
                if not ecosystem:
                    ecosystem = self._get_project_ecosystem()
                    logger.info(f"未指定生态系统，使用项目默认生态系统: {ecosystem}")
            
            # 标准化生态系统名称
            ecosystem_map = {
                'python': 'PyPI',
                'py': 'PyPI',
                'javascript': 'npm',
                'js': 'npm',
                'node': 'npm',
                'java': 'Maven',
                'go': 'Go',
                'golang': 'Go',
                'ruby': 'RubyGems',
                'rust': 'crates.io',
                'php': 'Packagist',
                'composer': 'Packagist',
                'swift': 'Swift',
                'dotnet': 'NuGet',
                'csharp': 'NuGet',
                'c#': 'NuGet'
            }
            ecosystem = ecosystem_map.get(ecosystem.lower(), ecosystem)
            
            # 构建请求数据
            request_data = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }
            
            # 如果有版本，添加到请求数据中
            if package_version:
                request_data["version"] = package_version
            else:
                # 如果没有版本，发送空字符串
                request_data["version"] = ""
            
            # 记录当前请求数据，便于调试
            # logger.info(f"OSV API请求数据: {request_data}")
            
            # 执行API请求，带重试
            for attempt in range(max_retries):
                try:
                    response = requests.post(
                        "https://api.osv.dev/v1/query",
                        json=request_data,
                        timeout=30
                    )
                    
                    # 检查响应状态码
                    if response.status_code == 200:
                        data = response.json()
                        
                        # 如果vulns字段存在且不为空
                        if "vulns" in data and data["vulns"]:
                            # 处理每个漏洞，确保ID正确处理
                            vulns = []
                            for vuln in data["vulns"]:
                                if "/" in vuln.get("id", ""):
                                    # 记录原始复合ID
                                    vuln["original_id"] = vuln["id"]
                                    # 使用第一个ID作为主ID
                                    first_id = vuln["id"].split("/")[0].strip()
                                    vuln["id"] = first_id
                                    logger.info(f"检测到复合ID: {vuln['original_id']}, 使用第一个ID作为主ID: {first_id}")
                                
                                # 添加到结果列表
                                vulns.append(vuln)
                            
                            # 丰富漏洞信息
                            return self._enrich_vulnerability_info(vulns)
                        
                        return []
                    
                    # 处理API错误
                    logger.warning(f"OSV API请求失败 (尝试 {attempt+1}/{max_retries}): 状态码 {response.status_code}, 请求体：{request_data}, 响应: {response.text}")
                    
                    # 如果是最后一次尝试，记录更详细的错误日志
                    if attempt == max_retries - 1:
                        logger.error(f"OSV API请求最终失败: 状态码 {response.status_code}, 请求体: {request_data}, 响应: {response.text}")
                    
                    # 指数退避重试
                    time.sleep(retry_delay * (2 ** attempt))
                    
                except Exception as e:
                    logger.warning(f"OSV API请求出现异常 (尝试 {attempt+1}/{max_retries}): {str(e)}")
                    
                    # 如果是最后一次尝试，记录更详细的错误日志
                    if attempt == max_retries - 1:
                        logger.error(f"OSV API请求最终失败，异常: {str(e)}")
                    
                    # 指数退避重试
                    time.sleep(retry_delay * (2 ** attempt))
            
            # 所有重试都失败，返回空列表
            logger.error(f"在多次尝试后未能从OSV API获取 {package_name} 的漏洞信息")
            return []
        
        except Exception as e:
            logger.error(f"处理包 {package_name} 的漏洞信息时出错: {str(e)}")
            return []
    
    def _enrich_vulnerability_info(self, vulns: List[Dict]) -> List[Dict]:
        """
        补充漏洞信息，添加CVE描述、严重程度等
        
        Args:
            vulns: 漏洞信息列表
            
        Returns:
            List[Dict]: 补充后的漏洞信息列表
        """
        if not vulns:
            return vulns
        
        # 使用线程池并行处理
        with ThreadPoolExecutor(max_workers=5) as executor:
            def enrich_single_vuln(vuln):
                # 如果不包含aliases字段，尝试通过旧接口获取
                if 'id' in vuln and ('aliases' not in vuln or not vuln['aliases']):
                    try:
                        vuln_id = vuln['id']
                        detailed_info = self._fetch_vuln_info(vuln_id)
                        
                        if detailed_info:
                            # 合并信息
                            enriched_vuln = copy.deepcopy(vuln)
                            for key, value in detailed_info.items():
                                if key not in enriched_vuln or not enriched_vuln[key]:  # 如果不存在或为空，则使用新值
                                    enriched_vuln[key] = value
                        
                        return enriched_vuln
                    except Exception as e:
                        logger.error(f"补充漏洞 {vuln['id']} 的信息时出错: {str(e)}")
                
                # 如果不需要补充或出错，返回原始数据
                return vuln
            
            # 提交所有任务
            enriched_vulns = list(executor.map(enrich_single_vuln, vulns))
        
        return enriched_vulns
    
    def _fetch_package_vulnerabilities_batch(self, packages: List[str]) -> Dict[str, List[Dict]]:
        """
        批量获取多个包的漏洞信息
        
        Args:
            packages: 包名列表
            
        Returns:
            Dict[str, List[Dict]]: 包名到漏洞信息列表的映射
        """
        
        result = {}
        package_details = []
        
        # 解析包名获取生态系统和版本信息
        for pkg in packages:
            
            # 尝试从包名中提取生态系统和版本信息
            # 常见格式: name@version, ecosystem:name:version, name:version
            ecosystem = None
            version = None
            name = pkg
            
            # 从SBOM中查找包信息
            pkg_obj = self.sbom_b.get_package_by_name(pkg)
            if pkg_obj:
                # 如果有版本信息，使用它
                if hasattr(pkg_obj, "version") and pkg_obj.version:
                    version = pkg_obj.version
                
                # 检查downloadLocation字段
                download_location = None
                if hasattr(pkg_obj, "download_location"):
                    download_location = pkg_obj.download_location
                elif hasattr(pkg_obj, "downloadLocation"):
                    download_location = pkg_obj.downloadLocation
                
                # 使用downloadLocation判断平台
                if download_location:
                    download_url = download_location.lower()
                    
                    # 判断平台
                    if "npmjs.com" in download_url or "npm.js" in download_url or "npm/package" in download_url:
                        ecosystem = "npm"
                        # logger.info(f"通过downloadLocation识别包 {pkg} 为npm包")
                    elif "pypi.org" in download_url or "python.org" in download_url:
                        ecosystem = "PyPI"
                        # logger.info(f"通过downloadLocation识别包 {pkg} 为PyPI包")
                    elif "maven" in download_url or "mvnrepository" in download_url:
                        ecosystem = "Maven"
                        # logger.info(f"通过downloadLocation识别包 {pkg} 为Maven包")
                    elif "golang.org" in download_url or "go.dev" in download_url or "go-lang" in download_url:
                        ecosystem = "Go"
                        # logger.info(f"通过downloadLocation识别包 {pkg} 为Go包")
                    elif "rubygems" in download_url or "ruby-lang" in download_url:
                        ecosystem = "RubyGems"
                        # logger.info(f"通过downloadLocation识别包 {pkg} 为RubyGems包")
                    elif "crates.io" in download_url or "rust-lang" in download_url:
                        ecosystem = "crates.io"
                        # logger.info(f"通过downloadLocation识别包 {pkg} 为Rust包")
                    elif "packagist" in download_url or "composer" in download_url:
                        ecosystem = "Packagist"
                        # logger.info(f"通过downloadLocation识别包 {pkg} 为PHP包")
                    elif "nuget" in download_url:
                        ecosystem = "NuGet"
                        # logger.info(f"通过downloadLocation识别包 {pkg} 为.NET包")
            
            # 检查包对象中的其他信息来判断生态系统
            if not ecosystem and pkg_obj:
                # 从purl字段判断
                if hasattr(pkg_obj, 'purl') and pkg_obj.purl:
                    purl = pkg_obj.purl
                    if 'pkg:npm' in purl:
                        ecosystem = 'npm'
                    elif 'pkg:pypi' in purl:
                        ecosystem = 'PyPI'
                    elif 'pkg:maven' in purl:
                        ecosystem = 'Maven'
                    elif 'pkg:golang' in purl:
                        ecosystem = 'Go'
            
            # 如果还没确定生态系统，使用默认生态系统
            if not ecosystem:
                ecosystem = self._get_project_ecosystem()
            
            # 标准化版本号
            if version:
                version = self._normalize_version(version)
            
            package_details.append({
                'name': name,
                'version': version,
                'ecosystem': ecosystem,
                'original': pkg
            })
        
        # 使用线程池并行查询每个包的漏洞信息
        with tqdm(total=len(package_details), desc="查询包漏洞信息", unit="个") as pbar:
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_pkg = {
                    executor.submit(
                        self._get_package_vulnerabilities, 
                        pkg['name'],
                        pkg['version'],
                        pkg['ecosystem']
                    ): pkg 
                    for pkg in package_details
                }
                
                for future in as_completed(future_to_pkg):
                    pkg = future_to_pkg[future]
                    try:
                        vulns = future.result()
                        if vulns:
                            result[pkg['original']] = vulns
                    except Exception as e:
                        logger.error(f"处理包 {pkg['original']} 的漏洞信息时出错: {str(e)}")
                    finally:
                        pbar.update(1)
        
        return result
    
    def _check_version_changed_vulnerabilities(self) -> Dict[str, List[Dict]]:
        """
        检查版本变更的包是否引入了新的漏洞
        
        Returns:
            Dict[str, List[Dict]]: 包名到漏洞信息列表的映射
        """
        
        # 收集版本变更的包
        version_changes = self.result.version_changes
        
        if not version_changes:
            return {}
        
        # 构建需要查询的包列表
        packages_to_check = []
        package_versions = {}
        
        for change in version_changes:
            pkg_name = change.package_name
            new_version = change.new_version
            
            # 标准化版本号
            if new_version:
                # 把包名和版本添加到要查询的列表中
                packages_to_check.append(pkg_name)
                package_versions[pkg_name] = new_version
        
        # 使用现有的批量查询方法获取漏洞信息
        if packages_to_check:
            logger.info(f"开始检查 {len(packages_to_check)} 个版本变更包的漏洞信息")
            all_vulns = self._fetch_package_vulnerabilities_batch(packages_to_check)
            
            # 只保留有漏洞的包
            result = {pkg: vulns for pkg, vulns in all_vulns.items() if vulns}
            logger.info(f"版本变更漏洞检查完成，发现 {len(result)} 个包存在漏洞")
            
            return result
        
        return {}
    
    def _clean_vulnerability_id(self, vuln_id: str) -> str:
        """
        清理漏洞ID，移除前缀并处理复合ID
        
        Args:
            vuln_id: 原始漏洞ID
            
        Returns:
            str: 清理后的漏洞ID
        """
        # 移除常见前缀
        prefixes_to_remove = [
            "Warn: Project is vulnerable to: "
        ]
        
        clean_id = vuln_id
        for prefix in prefixes_to_remove:
            if clean_id.startswith(prefix):
                clean_id = clean_id[len(prefix):]
                break
        
        # 如果是复合ID（如包含/），取第一个部分
        if "/" in clean_id:
            clean_id = clean_id.split("/")[0].strip()
            
        return clean_id.strip()