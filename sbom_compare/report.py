#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM报告生成器 - 生成SBOM比较报告
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import matplotlib.pyplot as plt
import networkx as nx
from tabulate import tabulate
from colorama import Fore, Style, init

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
            
            # 按风险级别分组
            risk_levels = ["high", "medium", "low"]
            for level in risk_levels:
                if level in self.result.risks and self.result.risks[level]:
                    lines.append(f"\n{level.upper()} 级别风险:")
                    
                    # 按供应链阶段分组
                    stage_risks = self._group_risks_by_stage(self.result.risks[level])
                    
                    # 先显示通用风险
                    if None in stage_risks:
                        for risk in stage_risks[None]:
                            lines.append(f"  - {risk.category}: {risk.description}")
                            lines.append(f"    受影响的包: {', '.join(risk.affected_packages[:5])}")
                            if len(risk.affected_packages) > 5:
                                lines.append(f"    ... 等共{len(risk.affected_packages)}个包")
                            lines.append(f"    建议: {risk.recommendation}")
                            lines.append("")
                    
                    # 显示特定阶段的风险
                    stages = ["source", "ci", "container", "end-to-end"]
                    for stage in stages:
                        if stage in stage_risks:
                            lines.append(f"  【{self._get_stage_name(stage)}阶段】")
                            for risk in stage_risks[stage]:
                                lines.append(f"  - {risk.category}: {risk.description}")
                                lines.append(f"    受影响的包: {', '.join(risk.affected_packages[:5])}")
                                if len(risk.affected_packages) > 5:
                                    lines.append(f"    ... 等共{len(risk.affected_packages)}个包")
                                lines.append(f"    建议: {risk.recommendation}")
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
        # 简单的HTML模板
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SBOM比较报告</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                }}
                h1 {{
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }}
                h2 {{
                    color: #2980b9;
                    margin-top: 30px;
                }}
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin: 20px 0;
                }}
                th, td {{
                    text-align: left;
                    padding: 12px;
                    border: 1px solid #ddd;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                tr:nth-child(even) {{
                    background-color: #f9f9f9;
                }}
                .risk-high {{
                    background-color: #FFEBEE;
                    border-left: 5px solid #F44336;
                    padding: 10px;
                    margin: 10px 0;
                }}
                .risk-medium {{
                    background-color: #FFF8E1;
                    border-left: 5px solid #FFC107;
                    padding: 10px;
                    margin: 10px 0;
                }}
                .risk-low {{
                    background-color: #E8F5E9;
                    border-left: 5px solid #4CAF50;
                    padding: 10px;
                    margin: 10px 0;
                }}
                .graph-container {{
                    text-align: center;
                    margin: 20px 0;
                }}
                .stats {{
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: space-between;
                    margin: 20px 0;
                }}
                .stat-box {{
                    background-color: #f2f2f2;
                    border-radius: 5px;
                    padding: 15px;
                    margin: 10px;
                    flex: 1 0 200px;
                    text-align: center;
                }}
                .stat-number {{
                    font-size: 2em;
                    font-weight: bold;
                    color: #3498db;
                }}
                .stage-header {{
                    background-color: #EBF5FB;
                    padding: 5px 10px;
                    margin: 15px 0 5px 0;
                    border-radius: 3px;
                    border-left: 5px solid #3498db;
                }}
                .stage-header h3 {{
                    margin: 5px 0;
                    color: #2980b9;
                }}
                .security-score {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }}
                .score-summary {{
                    font-size: 1.2em;
                    margin-bottom: 15px;
                    padding-bottom: 10px;
                    border-bottom: 1px solid #ddd;
                }}
                .total-score {{
                    font-size: 2.5em;
                    font-weight: bold;
                }}
                .score-grade {{
                    display: inline-block;
                    padding: 2px 15px;
                    border-radius: 20px;
                    font-weight: bold;
                    margin-left: 10px;
                    color: white;
                }}
                .grade-a {{
                    background-color: #4CAF50;
                }}
                .grade-b {{
                    background-color: #FFC107;
                }}
                .grade-c {{
                    background-color: #FF9800;
                }}
                .grade-d, .grade-f {{
                    background-color: #F44336;
                }}
                .category-score {{
                    margin-bottom: 10px;
                    padding: 10px;
                    border-radius: 5px;
                }}
                .category-score-high {{
                    background-color: #E8F5E9;
                }}
                .category-score-medium {{
                    background-color: #FFF8E1;
                }}
                .category-score-low {{
                    background-color: #FFEBEE;
                }}
                /* 可收缩表格样式 */
                .collapsible {{
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
                }}
                .collapsible:hover {{
                    background-color: #e6f2ff;
                }}
                .collapsible:after {{
                    content: '\\002B';
                    font-weight: bold;
                    font-size: 22px;
                    margin-left: 10px;
                }}
                .active:after {{
                    content: '\\2212';
                }}
                .content {{
                    padding: 0 18px;
                    max-height: 0;
                    overflow: hidden;
                    transition: max-height 0.2s ease-out;
                    background-color: white;
                    border-radius: 0 0 5px 5px;
                    border: 1px solid #ddd;
                    border-top: none;
                }}
                .content-visible {{
                    max-height: 500px;
                    overflow-y: auto;
                }}
            </style>
        </head>
        <body>
            <h1>SBOM比较报告</h1>
            <p><strong>生成时间:</strong> {timestamp}</p>
            <p><strong>SBOM A:</strong> {sbom_a_path}</p>
            <p><strong>SBOM B:</strong> {sbom_b_path}</p>

            {security_score_section}
            
            <h2>基本统计信息</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{added_count}</div>
                    <div>新增包</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{removed_count}</div>
                    <div>移除包</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{version_changes_count}</div>
                    <div>版本变更</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{license_changes_count}</div>
                    <div>许可证变更</div>
                </div>
            </div>

            {added_packages_section}
            {removed_packages_section}
            {version_changes_section}
            {license_changes_section}
            {supplier_changes_section}
            {dependency_graph_section}
            {risk_analysis_section}
            
            <!-- 可收缩表格脚本 -->
            <script>
                document.addEventListener('DOMContentLoaded', function() {{
                    var coll = document.getElementsByClassName("collapsible");
                    for (var i = 0; i < coll.length; i++) {{
                        coll[i].addEventListener("click", function() {{
                            this.classList.toggle("active");
                            var content = this.nextElementSibling;
                            if (content.classList.contains("content-visible")) {{
                                content.classList.remove("content-visible");
                                content.style.maxHeight = null;
                            }} else {{
                                content.classList.add("content-visible");
                                content.style.maxHeight = "500px";
                            }}
                        }});
                    }}
                }});
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
            <button class="collapsible">新增包 ({len(self.result.added_packages)}) <span style="font-size:14px;color:#666">点击展开/收起</span></button>
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
            <button class="collapsible">移除包 ({len(self.result.removed_packages)}) <span style="font-size:14px;color:#666">点击展开/收起</span></button>
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
                change_type = "主版本" if change.is_major else "次版本" if change.is_minor else "补丁版本" if change.is_patch else "一般变更"
                rows.append(f"<tr><td>{change.package_name}</td><td>{change.old_version}</td><td>{change.new_version}</td><td>{change_type}</td></tr>")
            
            version_changes_section = f"""
            <button class="collapsible">版本变更 ({len(self.result.version_changes)}) <span style="font-size:14px;color:#666">点击展开/收起</span></button>
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
            <button class="collapsible">许可证变更 ({len(self.result.license_changes)}) <span style="font-size:14px;color:#666">点击展开/收起</span></button>
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
            <button class="collapsible">供应商变更 ({len(self.result.supplier_changes)}) <span style="font-size:14px;color:#666">点击展开/收起</span></button>
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
            
            risk_levels = ["high", "medium", "low"]
            for level in risk_levels:
                if level in self.result.risks and self.result.risks[level]:
                    # 按供应链阶段分组
                    stage_risks = self._group_risks_by_stage(self.result.risks[level])
                    
                    # 通用风险
                    if None in stage_risks:
                        for risk in stage_risks[None]:
                            affected_packages = ", ".join(risk.affected_packages[:5])
                            if len(risk.affected_packages) > 5:
                                affected_packages += f"... 等共{len(risk.affected_packages)}个包"
                            
                            risk_items.append(f"""
                            <div class="risk-{level}">
                                <h3>{risk.category}</h3>
                                <p>{risk.description}</p>
                                <p><strong>受影响的包:</strong> {affected_packages}</p>
                                <p><strong>建议:</strong> {risk.recommendation}</p>
                            </div>
                            """)
                    
                    # 特定阶段的风险
                    stages = ["source", "ci", "container", "end-to-end"]
                    for stage in stages:
                        if stage in stage_risks:
                            stage_name = self._get_stage_name(stage)
                            risk_items.append(f"""
                            <div class="stage-header">
                                <h3>【{stage_name}阶段】</h3>
                            </div>
                            """)
                            
                            for risk in stage_risks[stage]:
                                affected_packages = ", ".join(risk.affected_packages[:5])
                                if len(risk.affected_packages) > 5:
                                    affected_packages += f"... 等共{len(risk.affected_packages)}个包"
                                
                                risk_items.append(f"""
                                <div class="risk-{level}">
                                    <h3>{risk.category}</h3>
                                    <p>{risk.description}</p>
                                    <p><strong>受影响的包:</strong> {affected_packages}</p>
                                    <p><strong>建议:</strong> {risk.recommendation}</p>
                                </div>
                                """)
            
            if risk_items:
                risk_analysis_section = f"""
                <h2>风险分析</h2>
                {"".join(risk_items)}
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
                
                details_html = ""
                if category.details:
                    details_html = f"<p><strong>详情:</strong> {'; '.join(category.details)}</p>"
                
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
        
        # 填充模板
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
            security_score_section=security_score_section
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