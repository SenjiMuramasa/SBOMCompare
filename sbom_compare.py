#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SBOM Compare - 比较软件物料清单文件并分析供应链风险

SBOM Compare 是一个命令行工具，用于：
1. 比较两个SBOM文件，分析依赖包的变更
2. 识别版本、许可证和供应商变更
3. 计算软件供应链安全评分
4. 获取漏洞信息（通过OSV和CVE API）
5. 生成详细的安全风险分析报告

支持的SBOM格式：
- SPDX JSON
- Syft JSON
- CycloneDX JSON

用法示例:
    python sbom_compare.py sbom_a.json sbom_b.json --format html
    python sbom_compare.py sbom_a.json sbom_b.json --github-org <org> --github-repo <repo> --type source_to_ci
"""

import argparse
import sys
import os
import logging
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init
import textwrap

from sbom_compare.parser import SBOMParser
from sbom_compare.comparator import SBOMComparator
from sbom_compare.risk_analyzer import RiskAnalyzer
from sbom_compare.report import ReportGenerator
from sbom_compare.scorer import SecurityScoreCalculator

# 初始化colorama
init()

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("sbom-compare")

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="比较两个SBOM文件并分析供应链风险",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            比较类型说明:
            - source_to_ci: 源代码到CI构建的SBOM比较
            - ci_to_container: CI构建到容器镜像的SBOM比较
            - source_to_container: 源代码到容器镜像的端到端SBOM比较
            - version_to_version: 同一软件包不同版本的SBOM比较
            """)
    )
    
    parser.add_argument("sbom_a", help="第一个SBOM文件路径")
    parser.add_argument("sbom_b", help="第二个SBOM文件路径")
    parser.add_argument(
        "--type",
        choices=["source_to_ci", "ci_to_container", "source_to_container", "version_to_version"],
        default="source_to_container",
        help="比较类型 (默认: source_to_container)",
    )
    parser.add_argument(
        "--github-org",
        help="GitHub组织名称，用于计算安全评分",
    )
    parser.add_argument(
        "--github-repo",
        help="GitHub仓库名称，用于计算安全评分",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "html", "json"],
        default="text",
        help="输出格式 (默认: text)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="输出文件路径 (默认: 根据格式自动生成)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="显示详细输出",
    )
    return parser.parse_args()

def validate_files(sbom_a_path, sbom_b_path):
    """验证SBOM文件是否存在"""
    if not os.path.exists(sbom_a_path):
        logger.error(f"文件不存在: {sbom_a_path}")
        return False
    
    if not os.path.exists(sbom_b_path):
        logger.error(f"文件不存在: {sbom_b_path}")
        return False
    
    return True

def get_default_report_filename(sbom_a_path, sbom_b_path, format_type, compare_type):
    """生成默认的报告文件名"""
    # 提取SBOM文件名（不含路径和扩展名）
    sbom_a_name = os.path.splitext(os.path.basename(sbom_a_path))[0]
    sbom_b_name = os.path.splitext(os.path.basename(sbom_b_path))[0]
    
    # 获取当前时间戳
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 构建报告文件名
    return f"sbom_compare_{sbom_a_name}_vs_{sbom_b_name}_{compare_type}_{timestamp}.{format_type}"

def ensure_report_dir():
    """确保报告目录存在"""
    report_dir = os.path.join(os.getcwd(), "report")
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        logger.info(f"创建报告目录: {report_dir}")
    return report_dir

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="比较两个SBOM文件并分析供应链风险",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            比较类型说明:
            - source_to_ci: 源代码到CI构建的SBOM比较
            - ci_to_container: CI构建到容器镜像的SBOM比较
            - source_to_container: 源代码到容器镜像的端到端SBOM比较
            - version_to_version: 同一软件包不同版本的SBOM比较
            """)
    )
    
    parser.add_argument("sbom_a", help="第一个SBOM文件路径")
    parser.add_argument("sbom_b", help="第二个SBOM文件路径")
    parser.add_argument(
        "--type",
        choices=["source_to_ci", "ci_to_container", "source_to_container", "version_to_version"],
        default="source_to_container",
        help="比较类型 (默认: source_to_container)",
    )
    parser.add_argument(
        "--github-org",
        help="GitHub组织名称，用于计算安全评分",
    )
    parser.add_argument(
        "--github-repo",
        help="GitHub仓库名称，用于计算安全评分",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "html", "json"],
        default="text",
        help="输出格式 (默认: text)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="输出文件路径 (默认: 根据格式自动生成)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="显示详细输出",
    )
    
    args = parser.parse_args()
    
    try:
        # 读取SBOM文件
        sbom_a = SBOMParser(os.path.join("sample_data", args.sbom_a)).parse()
        sbom_b = SBOMParser(os.path.join("sample_data", args.sbom_b)).parse()
        
        # 比较SBOM
        comparator = SBOMComparator(sbom_a, sbom_b)
        result = comparator.compare()
        
        # 风险分析
        if args.type != "generic":
            logger.info(f"执行风险分析 (类型: {args.type})")
            risk_analyzer = RiskAnalyzer(result, args.type)
            risks = risk_analyzer.analyze()
            result.risks = risks

        # 计算安全评分
        calculator = SecurityScoreCalculator(
            result, 
            source_type=args.type,
            github_org=args.github_org,
            github_repo=args.github_repo
        )
        security_score = calculator.calculate()
        result.security_score = security_score
        
        # 生成报告 - 默认输出到 report 目录
        report_generator = ReportGenerator(result)
        
        # 如果用户没有指定报告路径，使用默认路径
        if not args.output:
            # 确保报告目录存在
            report_dir = ensure_report_dir()
            
            # 生成默认文件名
            default_filename = get_default_report_filename(
                args.sbom_a, args.sbom_b, args.format, args.type
            )
            
            # 构建完整路径
            report_path = os.path.join(report_dir, default_filename)
            logger.info(f"使用默认报告路径: {report_path}")
        else:
            report_path = args.output
        
        # 生成报告
        logger.info(f"生成{args.format}格式报告: {report_path}")
        report_generator.generate(report_path, args.format)
        
        # 打印结果摘要
        report_generator.print_console_report()
        
        if args.type != "generic":
            print(f"\n供应链阶段比较类型: {args.type}")
            if args.type == "source_to_ci":
                print("比较源代码阶段与CI阶段SBOM差异")
            elif args.type == "ci_to_container":
                print("比较CI阶段与容器阶段SBOM差异")
            elif args.type == "source_to_container":
                print("比较源代码阶段与容器阶段SBOM差异（端到端）")
        
        # 打印安全评分
        if security_score:
            print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}软件供应链安全评分 (满分10分){Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
            
            # 安全等级颜色
            grade_color = Fore.GREEN
            if security_score.grade.startswith('B'):
                grade_color = Fore.YELLOW
            elif security_score.grade.startswith('C'):
                grade_color = Fore.RED
            elif security_score.grade.startswith('D') or security_score.grade.startswith('F'):
                grade_color = Fore.RED
            
            # 打印评分和等级
            percentage = (security_score.total_score / security_score.max_score) * 100
            print(f"{Fore.WHITE}总评分: {security_score.total_score:.1f}/10 "
                  f"({percentage:.1f}%) {grade_color}[{security_score.grade}]{Style.RESET_ALL}")
            
            # 打印分类评分
            print(f"\n{Fore.WHITE}分类评分:{Style.RESET_ALL}")
            for category_name, category in security_score.categories.items():
                cat_percentage = (category.score / category.max_score) * 100
                category_color = Fore.GREEN if cat_percentage >= 80 else Fore.YELLOW if cat_percentage >= 60 else Fore.RED
                print(f"  {category_color}{category.name}: {category.score:.1f}/{category.max_score:.1f} "
                      f"({cat_percentage:.1f}%){Style.RESET_ALL}")
                
                # 打印影响因素
                if category.impact_factors:
                    print(f"    影响因素: {', '.join(category.impact_factors)}")
            
            # 打印总结
            print(f"\n{Fore.WHITE}评分总结:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{security_score.summary}{Style.RESET_ALL}")
            
            # 打印报告路径信息
            print(f"\n{Fore.GREEN}报告已生成: {report_path}{Style.RESET_ALL}")
        
        logger.info("比较完成")
        return 0
    
    except Exception as e:
        logger.error(f"处理SBOM时出错: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main()) 