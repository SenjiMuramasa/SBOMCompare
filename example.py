#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM比较工具示例
"""

import os
import sys
import logging
from sbom_compare.parser import SBOMParser
from sbom_compare.comparator import SBOMComparator
from sbom_compare.risk_analyzer import RiskAnalyzer
from sbom_compare.report import ReportGenerator

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("sbom-compare-example")

def main():
    """主函数"""
    # 示例SBOM文件路径
    sample1_path = os.path.join("sample_data", "dagger.json")
    sample2_path = os.path.join("sample_data", "dagger-build.spdx.json")
    
    # 检查文件是否存在
    if not os.path.exists(sample1_path) or not os.path.exists(sample2_path):
        logger.error("示例SBOM文件不存在，请确保sample_data目录中包含示例文件")
        return 1
    
    try:
        # 解析SBOM文件
        logger.info(f"解析SBOM文件: {sample1_path}")
        parser_a = SBOMParser(sample1_path)
        sbom_a = parser_a.parse()
        
        logger.info(f"解析SBOM文件: {sample2_path}")
        parser_b = SBOMParser(sample2_path)
        sbom_b = parser_b.parse()
        
        # 比较SBOM
        logger.info("比较SBOM文件")
        comparator = SBOMComparator(sbom_a, sbom_b)
        comparison_result = comparator.compare()
        
        # 风险分析
        logger.info("执行风险分析")
        risk_analyzer = RiskAnalyzer(comparison_result)
        risks = risk_analyzer.analyze()
        comparison_result.risks = risks
        
        # 生成报告
        report_generator = ReportGenerator(comparison_result)
        
        # 生成文本报告
        text_report_path = "comparison_report.txt"
        logger.info(f"生成文本报告: {text_report_path}")
        report_generator.generate(text_report_path, "text")
        
        # 生成HTML报告
        html_report_path = "comparison_report.html"
        logger.info(f"生成HTML报告: {html_report_path}")
        report_generator.generate(html_report_path, "html")
        
        # 生成JSON报告
        json_report_path = "comparison_report.json"
        logger.info(f"生成JSON报告: {json_report_path}")
        report_generator.generate(json_report_path, "json")
        
        # 控制台打印摘要
        report_generator.print_console_report()
        
        logger.info("示例完成，生成的报告文件:")
        logger.info(f"  - 文本报告: {os.path.abspath(text_report_path)}")
        logger.info(f"  - HTML报告: {os.path.abspath(html_report_path)}")
        logger.info(f"  - JSON报告: {os.path.abspath(json_report_path)}")
        
        return 0
    
    except Exception as e:
        logger.error(f"处理SBOM时出错: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main()) 