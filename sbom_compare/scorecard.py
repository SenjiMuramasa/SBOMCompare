#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scorecard API 集成模块 - 获取项目的 Scorecard 评分
"""

import logging
import requests
from typing import Dict, Optional, Tuple

logger = logging.getLogger("sbom-compare.scorecard")

class ScorecardAPI:
    """Scorecard API 客户端"""
    
    BASE_URL = "https://api.securityscorecards.dev"
    
    def __init__(self):
        """初始化 Scorecard API 客户端"""
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "SBOM-Compare/1.0"
        })
    
    def get_project_score(self, org: str, project: str) -> Tuple[Optional[float], Optional[Dict]]:
        """
        获取项目的 Scorecard 评分
        
        Args:
            org: GitHub 组织名称
            project: GitHub 项目名称
            
        Returns:
            Tuple[Optional[float], Optional[Dict]]: (总分, 详细评分数据)
            如果请求失败则返回 (None, None)
        """
        try:
            url = f"{self.BASE_URL}/projects/github.com/{org}/{project}"
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            score = data.get("score", 0.0)
            return score, data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"获取 Scorecard 评分失败: {str(e)}")
            return None, None
    
    def get_check_scores(self, data: Dict) -> Dict[str, float]:
        """
        从评分数据中提取各检查项的得分
        
        Args:
            data: Scorecard API 返回的完整数据
            
        Returns:
            Dict[str, float]: 检查项名称到得分的映射
        """
        check_scores = {}
        if not data or "checks" not in data:
            return check_scores
            
        for check in data["checks"]:
            name = check.get("name", "")
            score = check.get("score", 0.0)
            check_scores[name] = score
            
        return check_scores
    
    def get_important_checks(self, check_scores: Dict[str, float]) -> Dict[str, str]:
        """
        获取重要检查项的状态评估
        
        Args:
            check_scores: 检查项得分字典
            
        Returns:
            Dict[str, str]: 重要检查项及其状态描述
        """
        status = {}
        
        # 定义重要检查项的阈值
        thresholds = {
            "Dependency-Update-Tool": 7.0,  # 依赖更新工具
            "CII-Best-Practices": 7.0,      # CII最佳实践
            "Vulnerabilities": 8.0,         # 漏洞
            "Binary-Artifacts": 8.0,        # 二进制制品
            "Branch-Protection": 7.0,       # 分支保护
            "Code-Review": 7.0,             # 代码审查
            "Dangerous-Workflow": 9.0,      # 危险的工作流
            "Maintained": 7.0,              # 维护状态
            "Token-Permissions": 8.0,       # 令牌权限
            "Security-Policy": 7.0          # 安全策略
        }
        
        for check, threshold in thresholds.items():
            if check in check_scores:
                score = check_scores[check]
                if score >= threshold:
                    status[check] = "良好"
                elif score >= threshold - 3:
                    status[check] = "需要改进"
                else:
                    status[check] = "风险较高"
                    
        return status 