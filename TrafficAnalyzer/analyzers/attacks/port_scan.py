from typing import List, Dict, Any
from ...core.strategy import BaseAnalyzer

class PortScanAnalyzer(BaseAnalyzer):
    def __init__(self, threshold=10, time_window=5.0):
        super().__init__("PortScan", "检测 Nmap 风格的端口扫描 (单源 -> 多目的端口)")
        self.threshold = threshold
        self.time_window = time_window

    @property
    def grouping_key(self) -> str:
        # 按源 IP 分组
        return 'src_ip'

    def match_type(self, packet_meta: Dict) -> bool:
        # 检查是否为 TCP 或 UDP 且有端口
        if 'dst_port' in packet_meta and packet_meta.get('dst_port') != 0:
            return True
        return False

    def analyze_parallel(self, packet_meta: Dict) -> Dict:
        # 提取目的端口
        return {
            'dst_port': packet_meta.get('dst_port'),
            'proto': packet_meta.get('proto')
        }

    def analyze_serial(self, flow_data: List[Dict]) -> List[str]:
        # 输入: 单个 src_ip 的特征列表，按时间排序
        if not flow_data:
            return []
            
        alerts = []
        window = []
        
        # 优化: 如果总唯一端口数 < 阈值，直接跳过
        all_ports = set(r.get('dst_port') for r in flow_data)
        if len(all_ports) <= self.threshold:
            return []
            
        # 滑动窗口
        for record in flow_data:
            ts = record['timestamp']
            
            # 加入窗口
            window.append(record)
            
            # 移除时间窗口外的旧记录
            while window and (ts - window[0]['timestamp'] > self.time_window):
                window.pop(0)
            
            # 检查当前窗口内的唯一端口
            unique_ports = set(p['dst_port'] for p in window)
            
            if len(unique_ports) > self.threshold:
                src = record.get('src_ip', '未知')
                msg = f"检测到潜在端口扫描，源IP: {src}, {self.time_window}秒内连接了 {len(unique_ports)} 个唯一端口"
                if msg not in alerts:
                    alerts.append(msg)
                
                # 可选: 清空窗口或跳过以避免警报泛滥
                # window = [] 
                
        return alerts
