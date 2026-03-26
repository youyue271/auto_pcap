from typing import Dict, Tuple

def get_five_tuple(packet_meta: Dict) -> Tuple:
    """
    计算五元组 (src_ip, dst_ip, src_port, dst_port, proto)
    统一方向：sort(src, dst) 以保证双向流归为同一个 Flow ID
    """
    src = packet_meta.get('src_ip')
    dst = packet_meta.get('dst_ip')
    sport = packet_meta.get('src_port')
    dport = packet_meta.get('dst_port')
    proto = packet_meta.get('proto')

    if src is None or dst is None:
        return None

    # 简单处理：如果是 IP 包但没有端口（如 ICMP），端口设为 0
    if sport is None: sport = 0
    if dport is None: dport = 0
    
    # 规范化：小的在前，大的在后，保证双向通信属于同一个 flow
    if src > dst:
        src, dst = dst, src
        sport, dport = dport, sport

    return (src, dst, sport, dport, proto)

def get_flow_id(packet_meta: Dict) -> str:
    """
    生成 Flow ID 字符串
    """
    ft = get_five_tuple(packet_meta)
    if ft:
        return f"{ft[0]}:{ft[2]}-{ft[1]}:{ft[3]}-{ft[4]}"
    return "unknown"
