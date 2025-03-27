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
from typing import Dict, List, Any, Optional
from datetime import datetime
import matplotlib.pyplot as plt
import networkx as nx
from tabulate import tabulate
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from lxml import html
from tqdm import tqdm

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
        
        # 缓存漏洞查询结果
        self.vulnerability_cache = {}
        # 新增包的漏洞信息缓存
        self.added_packages_vulnerabilities = None
    
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
        """从OSV API获取漏洞详细信息
        
        Args:
            vuln_id: 漏洞ID
            
        Returns:
            Optional[Dict]: 漏洞详细信息
        """
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"获取漏洞 {vuln_id} 详细信息失败: {str(e)}")
        return None
        
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

    def _process_vulnerabilities(self, scorecard_category) -> List[Dict]:
        """处理漏洞信息，使用多线程并行获取详细信息
        
        Args:
            scorecard_category: Scorecard评估类别
            
        Returns:
            List[Dict]: 处理后的漏洞信息列表
        """
        vulnerabilities = []
        vuln_details = []
        start_time = time.time()
        
        # 收集所有需要获取信息的漏洞ID
        print("开始收集漏洞ID...")
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
        
        if not vuln_details:
            print("未发现漏洞")
            return []
        
        print(f"发现 {len(vuln_details)} 个漏洞需要处理")
        
        # 使用线程池并行获取所有漏洞的OSV信息
        osv_results = {}
        all_cve_ids = set()
        
        with tqdm(total=len(vuln_details), desc="获取OSV信息", unit="个") as pbar:
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
                    finally:
                        pbar.update(1)
        
        # 并行获取所有CVE信息
        cve_results = {}
        if all_cve_ids:
            print(f"发现 {len(all_cve_ids)} 个CVE ID需要获取详情")
            cve_results = self._fetch_cve_info_batch(list(all_cve_ids))
        
        # 整合OSV和CVE信息
        print("整合漏洞信息...")
        with tqdm(total=len(osv_results), desc="整合漏洞信息", unit="个") as pbar:
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
                pbar.update(1)
        
        end_time = time.time()
        print(f"处理 {len(vulnerabilities)} 个漏洞完成，耗时 {end_time - start_time:.2f} 秒")
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
            
            # 检查是否因为漏洞严重程度限制了评分
            vuln_limit_html = ""
            
            # 获取新增包的漏洞信息，使用已有缓存
            if self.added_packages_vulnerabilities:
                pkg_vulns = self.added_packages_vulnerabilities
            else:
                pkg_vulns = self._fetch_package_vulnerabilities_batch(self.result.added_packages)
            
            # 检查漏洞严重程度
            has_critical = False
            has_high = False
            has_medium = False
            
            for pkg_name, vulns in pkg_vulns.items():
                for vuln in vulns:
                    # 获取漏洞严重程度
                    severity = "unknown"
                    if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                        severity = vuln["database_specific"]["severity"]
                    elif "severity" in vuln:
                        # 处理severity字段是列表的情况
                        if isinstance(vuln["severity"], list):
                            for sev_item in vuln["severity"]:
                                if isinstance(sev_item, dict) and "type" in sev_item and sev_item.get("type") == "CVSS_V3":
                                    severity = sev_item.get("score", "unknown")
                                    break
                        else:
                            severity = vuln["severity"]
                    
                    # 根据严重程度调整评分上限
                    if severity == "CRITICAL":
                        has_critical = True
                        break
                    elif severity == "HIGH":
                        has_high = True
                    elif severity == "MEDIUM":
                        has_medium = True
            
            # 显示漏洞限制评分的说明
            if has_critical:
                vuln_limit_html = """
                <div class="vuln-critical" style="margin-top: 15px; padding: 10px; border-radius: 5px; border: 1px solid #d32f2f;">
                    <strong>⚠️ 评分限制:</strong> 由于新增包中存在严重级别(CRITICAL)漏洞，评分被限制在4分以内。
                </div>
                """
            elif has_high:
                vuln_limit_html = """
                <div class="vuln-high" style="margin-top: 15px; padding: 10px; border-radius: 5px; border: 1px solid #f44336;">
                    <strong>⚠️ 评分限制:</strong> 由于新增包中存在高危级别(HIGH)漏洞，评分被限制在6分以内。
                </div>
                """
            elif has_medium:
                vuln_limit_html = """
                <div class="vuln-medium" style="margin-top: 15px; padding: 10px; border-radius: 5px; border: 1px solid #ff9800;">
                    <strong>⚠️ 评分限制:</strong> 由于新增包中存在中危级别(MEDIUM)漏洞，评分被限制在8分以内。
                </div>
                """
            
            security_score_section = f"""
            <h2>软件供应链安全评分</h2>
            <div class="security-score">
                <div class="score-summary">
                    <span class="total-score">{security_score.total_score:.1f}/10</span>
                    <span class="score-percentage">({percentage:.1f}%)</span>
                    <span class="score-grade {grade_class}">{security_score.grade}</span>
                </div>
                
                {vuln_limit_html}
                
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
            if self.added_packages_vulnerabilities:
                pkg_vulns = self.added_packages_vulnerabilities
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
                            refs_html = "<div class='vuln-refs'><strong>参考链接:</strong><br>" + "<br>".join([f"<a href='{url}' target='_blank' class='vuln-link'>{url}</a>" for url in references]) + "</div>"
                        
                        vuln_rows.append(f"""
                        <tr>
                            <td>{pkg_name}</td>
                            <td class="{severity_class}">{vuln_id}<br>{cve_info}</td>
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
        """
        规范化版本字符串，移除空格、前缀'v'和版本表达式前缀
        
        Args:
            version: 原始版本字符串
            
        Returns:
            str: 规范化后的版本字符串
        """
        if not version:
            return ""
        
        # 处理npm的范围表达式如 "1.0.0 - 2.0.0"
        if " - " in version:
            # 取表达式的第一部分
            version = version.split(" - ")[0].strip()
        
        # 标准化版本前缀符号周围的空格，如">= 1.0.0" 变为 ">=1.0.0"
        for op in [">=", "<=", ">", "<", "==", "~=", "!=", "~", "^"]:
            if op in version:
                # 去除操作符周围的空格
                version = version.replace(f"{op} ", op).replace(f" {op}", op)
        
        # 移除版本号中的所有空格
        version = version.replace(" ", "")
        
        # 去除版本表达式前缀（如 "==1.8.0" -> "1.8.0"）
        for op in [">=", "<=", ">", "<", "==", "~=", "!=", "~", "^"]:
            if version.startswith(op):
                version = version[len(op):]
                break
        
        # 去除前缀"v"
        if version.startswith('v'):
            version = version[1:]
        
        # 去除版本后的修饰符，如 "1.0.0-beta.1" -> "1.0.0"
        if "-" in version:
            parts = version.split("-")
            if all(c.isdigit() or c == '.' for c in parts[0]):
                version = parts[0]
        
        # 去除版本末尾的通配符
        version = version.rstrip('.*').rstrip('*')
        
        # 确保版本号不为空
        if not version and version != "0":
            version = "0"
        
        return version

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
        # 重试参数
        max_retries = 3
        retry_delay = 2  # 初始延迟2秒
        
        # 标准化版本号
        if package_version:
            package_version = self._normalize_version(package_version)
        
        # 标准化生态系统名称
        if ecosystem:
            # 生态系统名称映射
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
        
        for attempt in range(max_retries):
            try:
                # 构建OSV API请求数据
                # 按照样例 {"version": "0.1.0", "package": {"name": "flatmap-stream", "ecosystem": "npm"}}
                request_data = {
                    "package": {
                        "name": package_name
                    }
                }
                
                # 添加生态系统（如果提供）
                if ecosystem:
                    request_data["package"]["ecosystem"] = ecosystem
                    
                # 添加包版本（如果提供）
                if package_version:
                    request_data["version"] = package_version
                
                # 每次请求前增加延迟，避免频率限制
                if attempt > 0:
                    sleep_time = retry_delay * (2 ** (attempt - 1))  # 指数退避
                    logger.info(f"重试查询 {package_name} 的漏洞信息 (第{attempt+1}次尝试)，等待 {sleep_time} 秒")
                    time.sleep(sleep_time)
                
                logger.info(f"OSV API 请求体: {json.dumps(request_data)}")
                # 发送POST请求到OSV API
                response = requests.post(
                    "https://api.osv.dev/v1/query",
                    json=request_data,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"OSV API响应: 发现 {len(data.get('vulns', []))} 个漏洞")
                    if "vulns" in data and data["vulns"]:
                        return data["vulns"]
                    return []
                elif response.status_code == 429:  # Too Many Requests
                    logger.warning(f"查询包 {package_name} 的漏洞信息被限制，状态码: {response.status_code}")
                    # 请求被限制，稍后重试
                    continue
                else:
                    logger.warning(f"查询包 {package_name} 的漏洞信息失败，状态码: {response.status_code}，响应: {response.text}")
                    if attempt == max_retries - 1:
                        return []  # 最后一次尝试也失败
                    continue  # 继续尝试
            except Exception as e:
                logger.error(f"查询包 {package_name} 的漏洞信息时出错: {str(e)}")
                if attempt == max_retries - 1:
                    return []  # 最后一次尝试也失败
        
        return []  # 所有重试都失败

    def _fetch_package_vulnerabilities_batch(self, packages: List[str]) -> Dict[str, List[Dict]]:
        """
        批量获取多个包的漏洞信息
        
        Args:
            packages: 包名列表
            
        Returns:
            Dict[str, List[Dict]]: 包名到漏洞信息列表的映射
        """
        # 检查是否已有缓存结果
        if packages and all(pkg in self.vulnerability_cache for pkg in packages):
            logger.info("使用缓存的漏洞信息")
            # 构建结果字典，只包含请求的包
            return {pkg: self.vulnerability_cache.get(pkg, []) for pkg in packages}
        
        # 存储新增包的漏洞信息，便于后续复用
        if packages == self.result.added_packages and self.added_packages_vulnerabilities is not None:
            logger.info("使用已缓存的新增包漏洞信息")
            return self.added_packages_vulnerabilities
        
        result = {}
        package_details = []
        
        # 定义常见文件扩展名与生态系统的映射
        extension_to_ecosystem = {
            # Python
            '.py': 'PyPI',
            '.whl': 'PyPI',
            '.egg': 'PyPI',
            # JavaScript/Node.js
            '.js': 'npm',
            '.ts': 'npm',
            '.jsx': 'npm',
            '.tsx': 'npm',
            '.mjs': 'npm',
            '.cjs': 'npm',
            # Java
            '.jar': 'Maven',
            '.java': 'Maven',
            '.war': 'Maven',
            '.ear': 'Maven',
            '.pom': 'Maven',
            # Go
            '.go': 'Go',
            # Ruby
            '.rb': 'RubyGems',
            '.gem': 'RubyGems',
            # Rust
            '.rs': 'crates.io',
            # PHP
            '.php': 'Packagist',
            # .NET
            '.dll': 'NuGet',
            '.exe': 'NuGet',
            '.cs': 'NuGet',
            '.vb': 'NuGet',
        }
        
        # 包名前缀与生态系统的映射
        prefix_to_ecosystem = {
            'py-': 'PyPI',
            'python-': 'PyPI',
            'node-': 'npm',
            'js-': 'npm',
            'npm-': 'npm',
            'ruby-': 'RubyGems',
            'gem-': 'RubyGems',
            'go-': 'Go',
            'rust-': 'crates.io',
            'cargo-': 'crates.io',
            'php-': 'Packagist',
            'nuget-': 'NuGet',
            'dotnet-': 'NuGet'
        }
        
        # 从SBOM中提取更多信息的尝试
        sbom_ecosystems = {
            "javascript": "npm",
            "node.js": "npm",
            "nodejs": "npm",
            "js": "npm",
            "python": "PyPI",
            "java": "Maven",
            "golang": "Go",
            "ruby": "RubyGems",
            "rust": "crates.io",
            "php": "Packagist",
            ".net": "NuGet",
            "dotnet": "NuGet",
            "c#": "NuGet"
        }
        
        # 检查是否可以从SBOM信息中获取编程语言
        sbom_language = None
        if hasattr(self.sbom_b, "metadata") and self.sbom_b.metadata:
            if "programming_language" in self.sbom_b.metadata:
                lang = self.sbom_b.metadata["programming_language"].lower()
                sbom_language = sbom_ecosystems.get(lang)
        
        # 解析包名获取生态系统和版本信息
        for pkg in packages:
            # 如果已经在缓存中，跳过处理
            if pkg in self.vulnerability_cache:
                continue
            
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
            
            # 检查特定格式
            if '@' in pkg:  # npm格式: name@version
                name, version = pkg.split('@', 1)
                ecosystem = 'npm'
            elif ':' in pkg:  # Maven或其他格式
                parts = pkg.split(':')
                if len(parts) == 3:  # groupId:artifactId:version
                    ecosystem = 'Maven'
                    name = f"{parts[0]}:{parts[1]}"
                    version = parts[2]
                elif len(parts) == 2:  # name:version
                    name = parts[0]
                    version = parts[1]
            
            # 如果还没确定生态系统，尝试从名称或扩展名推断
            if not ecosystem:
                # 检查文件扩展名
                for ext, eco in extension_to_ecosystem.items():
                    if name.endswith(ext):
                        ecosystem = eco
                        # 移除扩展名
                        name = name[:-len(ext)]
                        break
                
                # 检查包名前缀
                if not ecosystem:
                    for prefix, eco in prefix_to_ecosystem.items():
                        if name.startswith(prefix):
                            ecosystem = eco
                            break
                
                    # 如果仍未确定，使用SBOM中的编程语言
                    if not ecosystem and sbom_language:
                        ecosystem = sbom_language
            
            # 如果包名看起来像npm包（包含连字符），但未确定生态系统，默认为npm
            if not ecosystem and ('-' in name or '/' in name) and not any(char.isupper() for char in name):
                ecosystem = 'npm'
            
            # 标准化版本号
            if version:
                version = self._normalize_version(version)
            
            logger.info(f"解析包 {pkg} 得到: name={name}, version={version}, ecosystem={ecosystem}")
            
            package_details.append({
                'name': name,
                'version': version,
                'ecosystem': ecosystem,
                'original': pkg
            })
        
        # 查找未在缓存中的包
        uncached_packages = [pkg['original'] for pkg in package_details]
        if not uncached_packages:
            logger.info("所有包都已缓存")
            return {pkg: self.vulnerability_cache.get(pkg, []) for pkg in packages}
        
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
                            # 更新缓存
                            self.vulnerability_cache[pkg['original']] = vulns
                        else:
                            # 没有漏洞也缓存空列表
                            self.vulnerability_cache[pkg['original']] = []
                    except Exception as e:
                        logger.error(f"处理包 {pkg['original']} 的漏洞信息时出错: {str(e)}")
                        # 出错时也缓存空列表，避免重复查询错误的包
                        self.vulnerability_cache[pkg['original']] = []
                    finally:
                        pbar.update(1)
        
        # 合并缓存结果
        for pkg in packages:
            if pkg not in result and pkg in self.vulnerability_cache:
                result[pkg] = self.vulnerability_cache[pkg]
        
        # 如果这是新增包的漏洞查询，保存结果以便复用
        if packages == self.result.added_packages:
            logger.info(f"缓存新增包的漏洞信息，共 {len(result)} 个包有漏洞")
            self.added_packages_vulnerabilities = result
            # 将漏洞信息添加到比较结果对象，方便评分计算器使用
            setattr(self.result, 'added_packages_vulnerabilities', result)
        
        return result