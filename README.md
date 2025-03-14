# SBOM Comparator

一个用于比较SPDX-2.3格式软件物料清单(SBOM)的工具，可以检测不同SBOM之间的差异，并分析这些差异可能表明的软件供应链问题。

## 功能特性

- 支持SPDX-2.3格式SBOM文件的解析
- 比较两个或多个SBOM文件的差异
- 识别包依赖、许可证、供应商和漏洞等方面的变化
- 分析差异可能指示的供应链风险
- 生成详细的比较报告
- 支持可视化显示差异和依赖关系

## 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/SBOMCompare.git
cd SBOMCompare

# 安装依赖
pip install -r requirements.txt
```

## 使用方法

比较两个SBOM文件：

```bash
python sbom_compare.py -a path/to/sbom1.spdx.json -b path/to/sbom2.spdx.json
```

生成详细报告：

```bash
python sbom_compare.py -a path/to/sbom1.spdx.json -b path/to/sbom2.spdx.json --report report.html
```

分析供应链风险：

```bash
python sbom_compare.py -a path/to/sbom1.spdx.json -b path/to/sbom2.spdx.json --risk-analysis
```

## 风险分析示例

SBOM比较可以揭示以下类型的供应链风险：

- **新增的依赖项**: 可能引入未审查的代码
- **移除的依赖项**: 可能表明代码被重写或功能被移除
- **版本变更**: 可能表明安全修复或功能变更
- **许可证变更**: 可能导致合规性问题
- **供应商变更**: 可能表明供应链被重定向
- **新增漏洞**: 软件可能引入已知的安全漏洞

## 输出示例

比较输出将包含以下部分：

- 基本统计信息 (包数量、许可证、供应商等)
- 新增和移除的包
- 版本变更的包
- 许可证变更
- 依赖关系变化
- 风险评估 