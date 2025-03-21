"""
SBOM Compare 工具 - 用于比较软件物料清单（SBOM）文件并分析供应链风险

SBOM Compare 是一个功能强大的软件工具，用于比较两个SBOM文件之间的差异，
分析依赖包变更，识别许可证合规性问题，计算供应链安全评分，并提供详细的漏洞信息。

主要功能：
- 比较SBOM文件，识别新增和移除的包
- 分析版本、许可证和供应商变更
- 计算软件供应链安全评分
- 获取漏洞信息（通过OSV和CVE API）
- 生成风险分析报告
- 支持多种输出格式（文本、HTML、JSON）

支持多种SBOM格式：
- SPDX JSON
- Syft JSON
- CycloneDX JSON
"""

__version__ = "0.2.0"
__author__ = "Wang Minjie"
__license__ = "MIT"
__project_url__ = "https://github.com/yourusername/sbom-compare"
__description__ = "比较SBOM文件并分析软件供应链安全风险的工具" 