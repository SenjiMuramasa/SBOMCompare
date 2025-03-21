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
from typing import Dict, List, Any, Optional
from datetime import datetime
import matplotlib.pyplot as plt
import networkx as nx
from tabulate import tabulate
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from lxml import html

from .comparator import ComparisonResult

# 初始化colorama
init()

logger = logging.getLogger("sbom-compare.report")

class ReportGenerator:
    """报告生成器类"""
    
    def __init__(self, comparison_result: ComparisonResult):
        self.result = comparison_result
        self.sbom_a = comparison_result.sbom_a
        self.sbom_b = comparison_result.sbom_b
    
    def generate(self, output_path: str, format_type: str = "text") -> None:
        """生成报告
        
        Args:
            output_path: 报告输出路径
            format_type: 报告格式，可以是 'text', 'html', 或 'json'
        """
        logger.info(f"生成{format_type}格式报告: {output_path}")
        
        if format_type == "text":
            self._generate_text_report(output_path)
        elif format_type == "html":
            self._generate_html_report(output_path)
        elif format_type == "json":
            self._generate_json_report(output_path)
        else:
            logger.error(f"不支持的报告格式: {format_type}")
            raise ValueError(f"不支持的报告格式: {format_type}")
    
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
                    lines.append(f"    详情: {'; '.join(category.details)}")
                if category.impact_factors:
                    lines.append(f"    影响因素: {', '.join(category.impact_factors)}")
            
            lines.append(f"\n评分总结: {security_score.summary}")
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
            
            for change in self.result.version_changes:
                # 规范化版本号进行比较
                normalized_old = self._normalize_version(change.old_version)
                normalized_new = self._normalize_version(change.new_version)
                
                # 当规范化后的版本相同时显示为"无变更"
                if normalized_old == normalized_new:
                    change_type = "无变更"
                else:
                    change_type = "主版本" if change.is_major else "次版本" if change.is_minor else "补丁版本" if change.is_patch else "一般变更"
                table_data.append([
                    change.package_name,
                    change.old_version,
                    change.new_version,
                    change_type
                ])
            
            lines.append(tabulate(table_data, headers=headers, tablefmt="grid"))
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
            
            # 计算总风险数量
            total_risks = sum(len(risks) for risks in all_stages.values())
            
            # 先处理通用风险（没有特定阶段）
            if all_stages[None]:
                for level, risk in all_stages[None]:
                    affected_packages = ", ".join(risk.affected_packages[:5])
                    if len(risk.affected_packages) > 5:
                        affected_packages += f"... 等共{len(risk.affected_packages)}个包"
                    
                    lines.append(f"{level.upper()} 级别风险:")
                    lines.append(f"  - {risk.category}: {risk.description}")
                    lines.append(f"    受影响的包: {affected_packages}")
                    lines.append(f"    建议: {risk.recommendation}")
                    lines.append("")
            
            # 处理按阶段分组的风险
            stages = ["source", "ci", "container", "end-to-end"]
            for stage in stages:
                if all_stages[stage]:  # 如果该阶段有风险
                    stage_name = self._get_stage_name(stage)
                    # 只添加一次阶段标题
                    lines.append(f"  【{stage_name}阶段】")
                    
                    # 按风险级别排序（高到低）
                    sorted_risks = sorted(all_stages[stage], key=lambda x: {"high": 0, "medium": 1, "low": 2}[x[0]])
                    
                    # 显示该阶段的所有风险
                    for level, risk in sorted_risks:
                        affected_packages = ", ".join(risk.affected_packages[:5])
                        if len(risk.affected_packages) > 5:
                            affected_packages += f"... 等共{len(risk.affected_packages)}个包"
                        
                        lines.append(f"  - {risk.category}: {risk.description}")
                        lines.append(f"    受影响的包: {affected_packages}")
                        lines.append(f"    建议: {risk.recommendation}")
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
    
    def _fetch_vuln_info(self, vuln_id: str) -> Optional[Dict]:
        """从OSV API获取漏洞信息
        
        Args:
            vuln_id: 漏洞ID，可能包含多个ID（用 / 分隔）
            
        Returns:
            Optional[Dict]: 漏洞信息，如果获取失败则返回None
        """
        # 处理多个漏洞ID的情况
        vuln_ids = [id.strip() for id in vuln_id.split('/')]
        
        for single_id in vuln_ids:
            try:
                # 移除前缀
                if single_id.startswith("Warn: Project is vulnerable to: "):
                    single_id = single_id[32:]
                
                response = requests.get(f"https://api.osv.dev/v1/vulns/{single_id}")
                if response.status_code == 200:
                    data = response.json()
                    # 如果成功获取到信息，添加其他ID作为别名
                    if "aliases" not in data:
                        data["aliases"] = []
                    # 将其他ID添加为别名，但不包括当前ID
                    other_ids = [id for id in vuln_ids if id != single_id]
                    if other_ids:
                        data["aliases"].extend(other_ids)
                    return data
                else:
                    print(f"Warning: Failed to fetch vulnerability info for {single_id}")
            except Exception as e:
                print(f"Error fetching vulnerability info for {single_id}: {str(e)}")
                continue
        
        print(f"Warning: Failed to fetch vulnerability info for all IDs: {vuln_id}")
        return None
    
    def _fetch_cve_info(self, cve_id: str) -> Optional[Dict]:
        """从CVE API获取漏洞详细信息
        
        Args:
            cve_id: CVE标识符，如"CVE-2021-44716"
            
        Returns:
            Optional[Dict]: 包含CVE详细信息的字典，如果获取失败则返回None
        """
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Warning: Failed to fetch CVE info for {cve_id} (Status code: {response.status_code})")
                return None
        except Exception as e:
            print(f"Error fetching CVE info for {cve_id}: {str(e)}")
            return None
    
    def _enhance_with_cve_info(self, description: str, osv_data: Dict) -> str:
        """使用CVE信息增强漏洞描述
        
        Args:
            description: 原始漏洞描述
            osv_data: OSV API返回的漏洞信息
            
        Returns:
            str: 增强后的漏洞描述
        """
        # 检查是否包含CVE ID
        cve_ids = []
        if "aliases" in osv_data:
            for alias in osv_data["aliases"]:
                if alias.startswith("CVE-"):
                    cve_ids.append(alias)
        
        # 如果找到CVE ID，获取详细信息
        for cve_id in cve_ids:
            cve_data = self._fetch_cve_info(cve_id)
            
            if cve_data:
                # 添加CVE信息标题
                description += f"\n\n来自 {cve_id} 的附加信息:"
                
                # 提取CVE描述
                try:
                    descriptions = cve_data["containers"]["cna"]["descriptions"]
                    for desc in descriptions:
                        if desc["lang"] == "en":
                            cve_description = desc["value"]
                            description += f"\n描述: {cve_description}"
                            break
                except (KeyError, IndexError):
                    pass
                
                # 提取发布和更新日期
                try:
                    published = cve_data["cveMetadata"]["datePublished"]
                    updated = cve_data["cveMetadata"]["dateUpdated"]
                    description += f"\n发布日期: {published[:10]}"
                    description += f"\n最后更新: {updated[:10]}"
                except (KeyError, IndexError):
                    pass
                
                # 提取参考链接
                try:
                    references = cve_data["containers"]["cna"]["references"]
                    if references:
                        description += "\nCVE参考链接:"
                        for ref in references[:5]:  # 最多显示5个链接
                            url = ref.get("url")
                            if url:
                                description += f"\n- {url}"
                except (KeyError, IndexError):
                    pass
                
                # 只处理第一个CVE ID
                break
        
        return description

    def _fetch_cve_info_batch(self, cve_ids: List[str]) -> Dict[str, Optional[Dict]]:
        """批量从CVE API获取漏洞详细信息
        
        Args:
            cve_ids: CVE标识符列表
            
        Returns:
            Dict[str, Optional[Dict]]: 包含CVE ID和对应详细信息的字典
        """
        results = {}
        
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
        
        return results

    def _process_vulnerabilities(self, scorecard_category) -> List[Dict]:
        """处理漏洞信息，使用多线程并行获取详细信息
        
        Args:
            scorecard_category: Scorecard评估类别
            
        Returns:
            List[Dict]: 处理后的漏洞信息列表
        """
        vulnerabilities = []
        vuln_details = []
        
        # 收集所有需要获取信息的漏洞ID
        for detail in scorecard_category.details:
            if detail.startswith("- "):
                # 解析漏洞信息
                vuln_info = detail[2:].split(" (")
                if len(vuln_info) == 2:
                    vuln_id = vuln_info[0]
                    severity_desc = vuln_info[1].split("): ")
                    if len(severity_desc) == 2:
                        severity = severity_desc[0]
                        description = severity_desc[1]
                        vuln_details.append({
                            "id": vuln_id,
                            "severity": severity,
                            "description": description
                        })
        
        # 使用线程池并行获取所有漏洞的OSV信息
        osv_results = {}
        all_cve_ids = set()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            # 提交所有OSV API查询任务
            future_to_vuln = {
                executor.submit(self._fetch_vuln_info, vuln["id"]): vuln 
                for vuln in vuln_details
            }
            
            # 获取所有OSV结果并收集需要查询的CVE IDs
            for future in as_completed(future_to_vuln):
                vuln = future_to_vuln[future]
                try:
                    osv_data = future.result()
                    osv_results[vuln["id"]] = {
                        "vuln": vuln,
                        "osv_data": osv_data
                    }
                    
                    # 收集所有需要查询的CVE ID
                    if osv_data and "aliases" in osv_data:
                        for alias in osv_data["aliases"]:
                            if alias.startswith("CVE-"):
                                all_cve_ids.add(alias)
                                break  # 每个漏洞只处理第一个CVE ID
                except Exception as e:
                    print(f"Error processing vulnerability {vuln['id']}: {str(e)}")
                    osv_results[vuln["id"]] = {
                        "vuln": vuln,
                        "osv_data": None
                    }
        
        # 并行获取所有CVE信息
        cve_results = {}
        if all_cve_ids:
            cve_results = self._fetch_cve_info_batch(list(all_cve_ids))
        
        # 整合OSV和CVE信息
        for vuln_id, result in osv_results.items():
            vuln = result["vuln"]
            osv_data = result["osv_data"]
            description = vuln["description"]
            
            if osv_data:
                # 添加别名信息
                if "aliases" in osv_data:
                    description += f"\n\n相关漏洞ID: {', '.join(osv_data['aliases'])}"
                
                # 添加发布日期
                if "published" in osv_data:
                    try:
                        published_date = datetime.fromisoformat(osv_data["published"].replace('Z', '+00:00'))
                        description += f"\n\n发布日期: {published_date.strftime('%Y-%m-%d')}"
                    except Exception:
                        pass
                
                # 添加参考链接
                if "references" in osv_data:
                    description += "\n\n参考链接:"
                    for ref in osv_data["references"]:
                        description += f"\n- {ref.get('url', '')}"
                
                # 添加漏洞类型
                if "type" in osv_data:
                    description += f"\n\n漏洞类型: {osv_data['type']}"
                
                # 添加影响范围
                if "affected" in osv_data:
                    description += "\n\n影响范围:"
                    for affected in osv_data["affected"]:
                        if "package" in affected:
                            description += f"\n- 包名: {affected['package'].get('name', 'N/A')}"
                            if "ecosystem" in affected["package"]:
                                description += f" ({affected['package']['ecosystem']})"
                
                # 添加CVE信息
                if "aliases" in osv_data:
                    for alias in osv_data["aliases"]:
                        if alias.startswith("CVE-") and alias in cve_results and cve_results[alias]:
                            cve_data = cve_results[alias]
                            
                            # 添加CVE信息标题
                            description += f"\n\n来自 {alias} 的附加信息:"
                            
                            # 提取CVE描述
                            try:
                                cve_descriptions = cve_data["containers"]["cna"]["descriptions"]
                                for desc in cve_descriptions:
                                    if desc["lang"] == "en":
                                        cve_description = desc["value"]
                                        description += f"\n描述: {cve_description}"
                                        break
                            except (KeyError, IndexError):
                                pass
                            
                            # 提取发布和更新日期
                            try:
                                published = cve_data["cveMetadata"]["datePublished"]
                                updated = cve_data["cveMetadata"]["dateUpdated"]
                                description += f"\n发布日期: {published[:10]}"
                                description += f"\n最后更新: {updated[:10]}"
                            except (KeyError, IndexError):
                                pass
                            
                            # 提取参考链接
                            try:
                                references = cve_data["containers"]["cna"]["references"]
                                if references:
                                    description += "\nCVE参考链接:"
                                    for ref in references[:5]:  # 最多显示5个链接
                                        url = ref.get("url")
                                        if url:
                                            description += f"\n- {url}"
                            except (KeyError, IndexError):
                                pass
                            
                            # 只处理第一个CVE ID
                            break
            else:
                # 如果OSV API获取失败，仍然添加原始漏洞ID作为相关漏洞ID
                if "/" in vuln["id"]:
                    related_ids = [id.strip() for id in vuln["id"].split("/")]
                    description += f"\n\n相关漏洞ID: {', '.join(related_ids)}"
                description += "\n\n获取漏洞详细信息失败"
            
            # 处理漏洞ID格式
            processed_vuln_id = vuln["id"]
            prefixes_to_remove = [
                "Warn: Project is vulnerable to: "
            ]
            for prefix in prefixes_to_remove:
                if processed_vuln_id.startswith(prefix):
                    processed_vuln_id = processed_vuln_id[len(prefix):]
            
            vulnerabilities.append({
                "id": processed_vuln_id,
                "severity": vuln["severity"],
                "description": description
            })
        
        return vulnerabilities
    
    def _generate_html_report(self, output_path: str) -> None:
        """生成HTML格式的报告"""
        # 创建依赖关系图
        if self.result.dependency_changes:
            self._generate_dependency_graph(os.path.dirname(output_path))
        
        html_content = self._get_html_report_content()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _get_html_report_content(self) -> str:
        """获取HTML报告内容"""
        # 定义CSS样式
        css_styles = """
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
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
            </div>
            
            <script>
                var coll = document.getElementsByClassName("collapsible");
                for (var i = 0; i < coll.length; i++) {{
                    coll[i].addEventListener("click", function() {{
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
            <button class="collapsible">
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
            <button class="collapsible">
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
            for change in self.result.version_changes:
                # 规范化版本号进行比较
                normalized_old = self._normalize_version(change.old_version)
                normalized_new = self._normalize_version(change.new_version)
                
                # 当规范化后的版本相同时显示为"无变更"
                if normalized_old == normalized_new:
                    change_type = "无变更"
                else:
                    change_type = "主版本" if change.is_major else "次版本" if change.is_minor else "补丁版本" if change.is_patch else "一般变更"
                
                rows.append(f"<tr><td>{change.package_name}</td><td>{change.old_version}</td><td>{change.new_version}</td><td>{change_type}</td></tr>")
            
            version_changes_section = f"""
            <button class="collapsible">
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
            <button class="collapsible">
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
        
        # 供应商变更部分
        supplier_changes_section = ""
        if self.result.supplier_changes:
            rows = []
            for change in self.result.supplier_changes:
                rows.append(f"<tr><td>{change.package_name}</td><td>{change.old_supplier}</td><td>{change.new_supplier}</td></tr>")
            
            supplier_changes_section = f"""
            <button class="collapsible">
                <span style="flex-grow: 1;">供应商变更 ({len(self.result.supplier_changes)})</span>
                <span style="font-size:14px;color:#666">点击展开/收起</span>
            </button>
            <div class="content">
                <table>
                    <tr>
                        <th>包名</th>
                        <th>旧供应商</th>
                        <th>新供应商</th>
                    </tr>
                    {"".join(rows)}
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
                for level, risk in all_stages[None]:
                    affected_packages = ", ".join(risk.affected_packages[:5])
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
                    sorted_risks = sorted(all_stages[stage], key=lambda x: {"high": 0, "medium": 1, "low": 2}[x[0]])
                    
                    # 显示该阶段的所有风险
                    for level, risk in sorted_risks:
                        affected_packages = ", ".join(risk.affected_packages[:5])
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
            
            if risk_items:
                risk_analysis_section = f"""
                <button class="collapsible">
                    <span style="flex-grow: 1;">风险分析 ({total_risks})</span>
                    <span style="font-size:14px;color:#666">点击展开/收起</span>
                </button>
                <div class="content">
                    <div class="risk-container">
                        {"".join(risk_items)}
                    </div>
                </div>
                """
        
        # 安全评分部分
        security_score_section = ""
        if hasattr(self.result, "security_score"):
            security_score = self.result.security_score
            percentage = (security_score.total_score / security_score.max_score) * 100
            
            # 确定等级样式类
            grade_class = ""
            if security_score.grade.startswith('A'):
                grade_class = "grade-a"
            elif security_score.grade.startswith('B'):
                grade_class = "grade-b"
            elif security_score.grade.startswith('C'):
                grade_class = "grade-c"
            elif security_score.grade.startswith('D') or security_score.grade.startswith('F'):
                grade_class = "grade-f"
            
            # 构建各分类的评分内容
            category_items = []
            for category_name, category in security_score.categories.items():
                cat_percentage = (category.score / category.max_score) * 100
                category_class = "category-score-high" if cat_percentage >= 80 else "category-score-medium" if cat_percentage >= 60 else "category-score-low"
                
                # 对于scorecard_assessment分类，过滤掉漏洞信息
                details = category.details
                if category_name == "scorecard_assessment":
                    details = [d for d in details if not d.startswith("- ")]
                
                details_html = ""
                if details:
                    details_html = f"<p><strong>详情:</strong> {'; '.join(details)}</p>"
                
                impact_html = ""
                if category.impact_factors:
                    impact_html = f"<p><strong>影响因素:</strong> {', '.join(category.impact_factors)}</p>"
                
                category_items.append(f"""
                <div class="category-score {category_class}">
                    <h3>{category.name}: {category.score:.1f}/{category.max_score:.1f} ({cat_percentage:.1f}%)</h3>
                    {details_html}
                    {impact_html}
                </div>
                """)
            
            security_score_section = f"""
            <h2>软件供应链安全评分</h2>
            <div class="security-score">
                <div class="score-summary">
                    <span class="total-score">{security_score.total_score:.1f}/10</span>
                    <span class="score-percentage">({percentage:.1f}%)</span>
                    <span class="score-grade {grade_class}">{security_score.grade}</span>
                </div>
                
                <div class="score-categories">
                    {"".join(category_items)}
                </div>
                
                <div class="score-summary-text">
                    <p><strong>评分总结:</strong> {security_score.summary}</p>
                </div>
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
                                    url = line[2:]
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
                            <td>{vuln['id']}</td>
                            <td>{description_html}</td>
                        </tr>
                        """)
                    
                    vulnerability_section = f"""
                    <button class="collapsible">
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
                        vuln_data = vuln["data"]
                        
                        # 初始化所有字段
                        severity = "未知"
                        description = ""
                        affected_versions = "所有版本"
                        published_date = ""
                        
                        # 提取漏洞描述
                        if "summary" in vuln_data:
                            description = vuln_data["summary"]
                        
                        # 提取发布日期
                        if "published" in vuln_data:
                            try:
                                published_date = vuln_data["published"][:10]  # 获取年月日部分
                            except:
                                published_date = ""
                        
                        # 提取相关CVE ID
                        cve_ids = []
                        if "upstream" in vuln_data:
                            cve_ids = [cve for cve in vuln_data["upstream"] if cve.startswith("CVE-")]
                        
                        # 提取影响版本范围
                        if "affected" in vuln_data:
                            for affected in vuln_data["affected"]:
                                if ("package" in affected and 
                                    "name" in affected["package"] and 
                                    affected["package"]["name"] == pkg_name):
                                    if "ranges" in affected:
                                        version_ranges = []
                                        for range_info in affected["ranges"]:
                                            if ("type" in range_info and 
                                                "events" in range_info):
                                                events = range_info["events"]
                                                introduced = "0"
                                                fixed = ""
                                                
                                                for event in events:
                                                    if "introduced" in event:
                                                        introduced = event["introduced"]
                                                    if "fixed" in event:
                                                        fixed = event["fixed"]
                                                
                                                if introduced and fixed:
                                                    version_ranges.append(f"{introduced} 到 {fixed}")
                                                elif introduced:
                                                    version_ranges.append(f">= {introduced}")
                                                elif fixed:
                                                    version_ranges.append(f"< {fixed}")
                                        
                                        if version_ranges:
                                            affected_versions = ", ".join(version_ranges)
                                    break
                        
                        # 构建引用链接列表
                        references = []
                        if "references" in vuln_data:
                            for ref in vuln_data["references"][:5]:  # 最多显示5个链接
                                if "url" in ref:
                                    references.append(ref["url"])
                        
                        # 添加到表格行
                        cve_info = f"关联CVE: {', '.join(cve_ids)}" if cve_ids else ""
                        refs_html = ""
                        if references:
                            refs_html = "<div class='vuln-refs'><strong>参考链接:</strong><br>" + "<br>".join([f"<a href='{url}' target='_blank'>{url}</a>" for url in references]) + "</div>"
                        
                        # 使用未知样式
                        severity_class = "vuln-unknown"
                        
                        vuln_rows.append(f"""
                        <tr>
                            <td>{pkg_name}</td>
                            <td>{vuln_id}<br>{cve_info}</td>
                            <td>{affected_versions}</td>
                            <td>{description}{refs_html}</td>
                            <td>{published_date}</td>
                        </tr>
                        """)
                
                # 创建表格
                if vuln_rows:
                    added_pkg_vulnerabilities_section = f"""
                    <button class="collapsible">
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
        
        # 在HTML模板中添加新增包漏洞信息部分
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
            report_data["version_changes"].append({
                "package_name": change.package_name,
                "old_version": change.old_version,
                "new_version": change.new_version,
                "is_major": change.is_major,
                "is_minor": change.is_minor,
                "is_patch": change.is_patch
            })
        
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
        
        # 写入JSON文件
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    def _generate_dependency_graph(self, output_dir: str) -> None:
        """生成依赖关系图
        
        将生成一个可视化图像，显示两个SBOM之间的依赖关系变化
        """
        try:
            # 创建一个有向图
            G = nx.DiGraph()
            
            # 添加节点和边
            # 使用不同颜色标记不同状态的节点
            for pkg_name in self.sbom_a.package_map.keys() | self.sbom_b.package_map.keys():
                if pkg_name in self.sbom_a.package_map and pkg_name not in self.sbom_b.package_map:
                    # 移除的包
                    G.add_node(pkg_name, color='red')
                elif pkg_name not in self.sbom_a.package_map and pkg_name in self.sbom_b.package_map:
                    # 新增的包
                    G.add_node(pkg_name, color='green')
                else:
                    # 保持不变的包
                    changed = False
                    for change in self.result.version_changes:
                        if change.package_name == pkg_name:
                            changed = True
                            break
                    
                    if changed:
                        G.add_node(pkg_name, color='orange')  # 版本变更
                    else:
                        G.add_node(pkg_name, color='blue')    # 无变化
            
            # 添加边表示依赖关系
            for pkg_name, deps in self.sbom_b.package_relationships.items():
                for dep in deps:
                    if pkg_name in G and dep in G:
                        G.add_edge(pkg_name, dep)
            
            # 使用spring布局
            pos = nx.spring_layout(G, seed=42)
            
            # 获取节点颜色
            node_colors = [G.nodes[n]['color'] for n in G.nodes()]
            
            plt.figure(figsize=(12, 10))
            nx.draw(
                G, 
                pos, 
                with_labels=True, 
                node_color=node_colors, 
                node_size=700, 
                font_size=8,
                font_weight='bold',
                arrowsize=15,
                edge_color='gray',
                alpha=0.8
            )
            
            # 添加图例
            from matplotlib.lines import Line2D
            legend_elements = [
                Line2D([0], [0], marker='o', color='w', label='新增包',
                        markerfacecolor='green', markersize=10),
                Line2D([0], [0], marker='o', color='w', label='移除包',
                        markerfacecolor='red', markersize=10),
                Line2D([0], [0], marker='o', color='w', label='版本变更',
                        markerfacecolor='orange', markersize=10),
                Line2D([0], [0], marker='o', color='w', label='无变化',
                        markerfacecolor='blue', markersize=10),
            ]
            plt.legend(handles=legend_elements, loc='upper right')
            
            plt.title("SBOM依赖关系变化图")
            plt.savefig(os.path.join(output_dir, "dependency_graph.png"), dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"依赖关系图已保存到 {os.path.join(output_dir, 'dependency_graph.png')}")
            
        except Exception as e:
            logger.error(f"生成依赖关系图失败: {e}", exc_info=True)
    
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

    def _get_package_vulnerabilities(self, package_name: str) -> List[str]:
        """
        获取包的漏洞ID列表
        
        Args:
            package_name: 包名
            
        Returns:
            List[str]: 漏洞ID列表
        """
        # 处理包名，移除前缀和特殊字符
        clean_name = package_name
        # 移除常见前缀
        prefixes = ['org.', 'com.', 'io.', 'net.']
        for prefix in prefixes:
            if clean_name.startswith(prefix):
                clean_name = clean_name[len(prefix):]
        # 替换路径分隔符为URL友好格式
        clean_name = clean_name.replace('/', '%2F').replace('_', '%5F')
        
        try:
            # 查询OSV网站获取漏洞列表
            url = f"https://osv.dev/list?q={clean_name}"
            response = requests.get(url)
            if response.status_code == 200:
                # 解析HTML内容
                tree = html.fromstring(response.content)
                # 使用XPath获取漏洞ID
                vuln_ids = tree.xpath('//div[@class="vuln-table-row mdc-data-table__row"]//a/text()')
                return vuln_ids
            else:
                logger.warning(f"获取包 {package_name} 的漏洞信息失败，状态码: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"获取包 {package_name} 的漏洞信息时出错: {str(e)}")
            return []
    
    def _fetch_vuln_batch(self, vuln_ids: List[str]) -> Dict[str, Optional[Dict]]:
        """
        批量获取漏洞详细信息
        
        Args:
            vuln_ids: 漏洞ID列表
            
        Returns:
            Dict[str, Optional[Dict]]: 漏洞ID到详细信息的映射
        """
        results = {}
        
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
        
        return results
    
    def _fetch_package_vulnerabilities_batch(self, packages: List[str]) -> Dict[str, List[Dict]]:
        """
        批量获取多个包的漏洞信息
        
        Args:
            packages: 包名列表
            
        Returns:
            Dict[str, List[Dict]]: 包名到漏洞信息列表的映射
        """
        result = {}
        all_vuln_ids = {}  # 映射漏洞ID到包名
        
        # 第一阶段：并行获取每个包的漏洞ID列表
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_pkg = {executor.submit(self._get_package_vulnerabilities, pkg): pkg for pkg in packages}
            
            for future in as_completed(future_to_pkg):
                pkg = future_to_pkg[future]
                try:
                    vuln_ids = future.result()
                    if vuln_ids:
                        for vuln_id in vuln_ids:
                            if vuln_id not in all_vuln_ids:
                                all_vuln_ids[vuln_id] = []
                            all_vuln_ids[vuln_id].append(pkg)
                except Exception as e:
                    logger.error(f"处理包 {pkg} 的漏洞列表时出错: {str(e)}")
        
        # 如果没有找到任何漏洞，直接返回
        if not all_vuln_ids:
            return {}
            
        # 第二阶段：并行获取所有漏洞的详细信息
        vuln_details = self._fetch_vuln_batch(list(all_vuln_ids.keys()))
        
        # 第三阶段：按包名组织漏洞信息
        for vuln_id, pkg_list in all_vuln_ids.items():
            vuln_data = vuln_details.get(vuln_id)
            if vuln_data:
                for pkg in pkg_list:
                    if pkg not in result:
                        result[pkg] = []
                    result[pkg].append({
                        "id": vuln_id,
                        "data": vuln_data
                    })
        
        return result