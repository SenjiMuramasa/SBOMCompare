#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM Compare 工具使用示例

这个示例演示了如何以编程方式使用SBOM Compare工具，
包括解析SBOM文件、比较差异、分析风险、计算安全评分和生成报告。
"""

import os
import sys
import logging
import time
from sbom_compare.parser import SBOMParser
from sbom_compare.comparator import SBOMComparator
from sbom_compare.risk_analyzer import RiskAnalyzer
from sbom_compare.report import ReportGenerator
from sbom_compare.scorer import SecurityScoreCalculator

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("sbom-compare-example")

def main():
    """示例主函数"""
    # 示例SBOM文件路径
    sample1_path = os.path.join("sample_data", "SBOMCompare_source.json")
    sample2_path = os.path.join("sample_data", "SenjiMuramasa_transformers.json")
    
    # 检查文件是否存在
    if not os.path.exists(sample1_path) or not os.path.exists(sample2_path):
        logger.error("示例SBOM文件不存在，请确保sample_data目录中包含示例文件")
        return 1
    
    try:
        # 解析SBOM文件
        start_time = time.time()
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
        
        # 输出基本比较结果
        logger.info(f"新增包数量: {len(comparison_result.added_packages)}")
        logger.info(f"移除包数量: {len(comparison_result.removed_packages)}")
        logger.info(f"版本变更数量: {len(comparison_result.version_changes)}")
        logger.info(f"许可证变更数量: {len(comparison_result.license_changes)}")
        
        # 计算安全评分（可选）
        try:
            logger.info("计算安全评分")
            github_org = "yourusername"  # 替换为您的GitHub组织名
            github_repo = "sbom-compare"  # 替换为您的GitHub仓库名
            
            scorer = SecurityScoreCalculator(comparison_result, github_org, github_repo)
            security_score = scorer.calculate()
            comparison_result.security_score = security_score
            
            logger.info(f"安全评分: {security_score.total_score}/10 ({security_score.grade})")
        except Exception as e:
            logger.warning(f"计算安全评分失败: {e}")
        
        # 风险分析
        logger.info("执行风险分析")
        risk_analyzer = RiskAnalyzer(comparison_result)
        risks = risk_analyzer.analyze()
        comparison_result.risks = risks
        
        if risks:
            logger.info("发现的风险:")
            for level, level_risks in risks.items():
                logger.info(f"{level.upper()} 级别风险: {len(level_risks)}个")
        
        # 生成报告
        report_generator = ReportGenerator(comparison_result)
        
        # 创建输出目录
        output_dir = "report"
        os.makedirs(output_dir, exist_ok=True)
        
        # 生成文本报告
        text_report_path = os.path.join(output_dir, "comparison_report.txt")
        logger.info(f"生成文本报告: {text_report_path}")
        report_generator.generate(text_report_path, "text")
        
        # 生成HTML报告
        html_report_path = os.path.join(output_dir, "comparison_report.html")
        logger.info(f"生成HTML报告: {html_report_path}")
        report_generator.generate(html_report_path, "html")
        
        # 生成JSON报告
        json_report_path = os.path.join(output_dir, "comparison_report.json")
        logger.info(f"生成JSON报告: {json_report_path}")
        report_generator.generate(json_report_path, "json")
        
        # 控制台打印摘要
        report_generator.print_console_report()
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        logger.info("示例完成，生成的报告文件:")
        logger.info(f"  - 文本报告: {os.path.abspath(text_report_path)}")
        logger.info(f"  - HTML报告: {os.path.abspath(html_report_path)}")
        logger.info(f"  - JSON报告: {os.path.abspath(json_report_path)}")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        
        return 0
    
    except Exception as e:
        logger.error(f"处理SBOM时出错: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main()) 