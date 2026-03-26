from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseAnalyzer(ABC):
    """
    所有分析策略的基类。
    """
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @property
    def grouping_key(self) -> str:
        """
        定义 Serial 阶段的聚合键。
        默认是 'flow_id' (五元组)。
        如果做端口扫描检测，可能需要 override 为 'src_ip'。
        """
        return 'flow_id'

    @abstractmethod
    def match_type(self, packet_meta: Dict) -> bool:
        """
        [快速过滤] 判断该策略是否需要处理这个包。
        例如：如果是 SQL 爆破分析，这里只返回 packet_meta.get('proto') == 'TCP'
        """
        pass

    @abstractmethod
    def analyze_parallel(self, packet_meta: Dict) -> Dict:
        """
        [并行部分] 无状态特征提取。
        输入：单包元数据
        输出：提取的特征 (Feature Vector)
        注意：这里不要做跨包分析，只做当前包的解析。
        返回 None 表示该包虽然匹配但不产生特征（可选）。
        """
        pass

    @abstractmethod
    def analyze_serial(self, flow_data: List[Dict]) -> List[Dict]:
        """
        [串行部分] 时序/状态分析。
        输入：一组按时间排序的特征数据 (属于同一个 Flow 或 同一个 IP)
        输出：分析结果 (警报列表 / 报告)
        """
        pass
