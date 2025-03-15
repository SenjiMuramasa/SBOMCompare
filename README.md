# SBOM Compare

SBOM Compare 是一个用于比较两个软件物料清单（SBOM）的工具，支持分析依赖包的变更、许可证合规性、供应链安全评分等。

## 功能特点

### 1. 基础比较
- 检测新增和移除的包
- 分析版本变更（主版本、次版本、补丁版本）
- 识别许可证变更和兼容性问题
- 追踪供应商变更
- 分析依赖关系变化

### 2. 安全评估
- 软件供应链安全评分（满分10分）
- 多维度评估指标
  - 源代码安全性
  - CI/CD流程安全性
  - 容器镜像安全性
  - 端到端供应链安全性
- 详细的评分解释和改进建议

### 3. 漏洞分析
- 自动获取漏洞信息（通过OSV API）
- 多线程并行处理提升性能
- 支持多种漏洞ID格式
- 按严重程度分类统计
- 提供漏洞详细信息
  - 相关漏洞ID
  - 发布日期
  - 参考链接
  - 漏洞类型
  - 影响范围

### 4. 风险分析
- 分级风险评估（高、中、低）
- 按供应链阶段分类
- 提供具体的风险描述和改进建议
- 识别受影响的包

### 5. 可视化
- 生成依赖关系变化图
- 直观展示包之间的依赖关系
- 使用不同颜色标识变更状态
  - 绿色：新增包
  - 红色：移除包
  - 橙色：版本变更
  - 蓝色：无变化

### 6. 多种报告格式
- HTML格式（交互式）
  - 可折叠的详细信息
  - 清晰的表格展示
  - 按严重程度着色
  - 响应式设计
- 文本格式（命令行友好）
- JSON格式（便于集成）

## 使用方法

### 基本用法

```bash
python sbom_compare.py <sbom_a.json> <sbom_b.json> [options]
```

### 命令行参数

- `--format`: 指定输出格式（html/text/json），默认为text
- `--output`: 指定输出文件路径
- `--github-org`: 指定GitHub组织名（用于安全评分）
- `--github-repo`: 指定GitHub仓库名（用于安全评分）
- `-t/--target`: 指定目标类型（source_to_ci/ci_to_container）

### 示例

比较源代码和CI阶段的SBOM，生成HTML报告：
```bash
python sbom_compare.py syft_sbom.json syft-build.spdx.json --github-org myorg --github-repo myrepo -t source_to_ci --format html
```

## 报告内容

### HTML报告包含：
1. 基本统计信息
   - 新增包数量
   - 移除包数量
   - 版本变更数量
   - 许可证变更数量
   - 漏洞数量

2. 软件供应链安全评分
   - 总分和等级
   - 各维度详细评分
   - 评分说明和建议

3. 漏洞风险总结
   - 漏洞总数统计
   - 按严重程度分布
   - 详细漏洞信息

4. 变更详情
   - 新增包列表
   - 移除包列表
   - 版本变更详情
   - 许可证变更信息
   - 供应商变更记录

5. 依赖关系图
   - 可视化展示依赖变化
   - 清晰的颜色标识

## 依赖要求

- Python 3.7+
- 主要依赖包：
  - requests
  - matplotlib
  - networkx
  - tabulate
  - colorama

## 安装

1. 克隆仓库：
```bash
git clone https://github.com/yourusername/sbom-compare.git
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

## 注意事项

1. 支持的SBOM格式：
   - SPDX JSON
   - Syft JSON
   - CycloneDX JSON

2. 漏洞信息获取：
   - 使用OSV API
   - 支持多线程并行处理
   - 自动处理多ID格式

3. 性能考虑：
   - 大型SBOM比较可能需要较长时间
   - 建议使用SSD存储生成的报告
   - 注意网络连接状态（用于获取漏洞信息）

## 贡献

欢迎提交Issue和Pull Request来帮助改进这个工具。

## 许可证

MIT License 