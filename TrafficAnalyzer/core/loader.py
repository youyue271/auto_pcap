from typing import Generator, Dict, Any
import logging
import asyncio

logger = logging.getLogger(__name__)

def packet_to_dict(packet) -> Dict[str, Any]:
    """
    将 Pyshark Packet 对象转换为轻量级 Dict
    """
    try:
        meta = {
            'timestamp': float(packet.sniff_timestamp),
            'length': int(packet.length),
            'highest_layer': packet.highest_layer,
            'transport_layer': getattr(packet, 'transport_layer', None),
            'layers': [l.layer_name for l in packet.layers]
        }
        
        # IP 层
        if hasattr(packet, 'ip'):
            meta['src_ip'] = packet.ip.src
            meta['dst_ip'] = packet.ip.dst
            meta['proto'] = packet.ip.proto # 协议号
        elif hasattr(packet, 'ipv6'):
            meta['src_ip'] = packet.ipv6.src
            meta['dst_ip'] = packet.ipv6.dst
            meta['proto'] = packet.ipv6.nxt # 下一头部
            
        # 传输层
        if hasattr(packet, 'tcp'):
            meta['src_port'] = int(packet.tcp.srcport)
            meta['dst_port'] = int(packet.tcp.dstport)
            meta['flags'] = packet.tcp.flags
        elif hasattr(packet, 'udp'):
            meta['src_port'] = int(packet.udp.srcport)
            meta['dst_port'] = int(packet.udp.dstport)
            
        return meta
    except Exception as e:
        # logger.error(f"数据包转换错误: {e}")
        return None

class PcapLoader:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def split_pcap(self, target_chunk_size_mb=0.5) -> list:
        """
        使用 editcap 将 PCAP 文件分割成多个小文件。
        策略: 根据文件大小动态计算切分数量，使每个文件约为 target_chunk_size_mb (默认 0.5MB)。
        """
        import subprocess
        import os
        import glob
        import math
        
        # 1. 获取文件大小 (MB)
        file_size_bytes = os.path.getsize(self.pcap_path)
        file_size_mb = file_size_bytes / (1024 * 1024)
        
        # 2. 计算目标切分数量
        # 如果文件小于目标大小，至少分1块(不分)
        if file_size_mb <= target_chunk_size_mb:
            chunk_count = 1
        else:
            chunk_count = math.ceil(file_size_mb / target_chunk_size_mb)
            
        logger.info(f"PCAP 大小: {file_size_mb:.2f}MB, 目标分块大小: {target_chunk_size_mb}MB, 预计分块数: {chunk_count}")
        
        if chunk_count <= 1:
            return [self.pcap_path]

        # 3. 获取总包数 (使用 capinfos)
        # capinfos -T -c -r <file>  -> 输出纯数字
        total_packets = 0
        try:
            cmd_count = ["capinfos", "-T", "-c", "-r", self.pcap_path]
            output = subprocess.check_output(cmd_count).decode().strip()
            # capinfos -T 可能会输出文件名和数字，例如 "tests/file.pcapng\t7106"
            # 或者如果只是 -c -r 可能只有数字。
            # 根据错误日志 "invalid literal for int() with base 10: 'tests/file.pcapng\t7106'"
            # 我们需要分割字符串
            if "\t" in output:
                total_packets = int(output.split("\t")[-1])
            else:
                total_packets = int(output)
        except Exception as e:
            logger.warning(f"无法使用 capinfos 获取包数: {e}，尝试使用文件大小估算...")
            # 估算: 假设平均包大小 800 bytes
            total_packets = int(file_size_bytes / 800)
            
        packets_per_file = math.ceil(total_packets / chunk_count)
        logger.info(f"总包数: {total_packets}, 每个分块约: {packets_per_file} 包")
        
        output_prefix = self.pcap_path.rsplit('.', 1)[0] + "_part"
        # 清理旧的分割文件
        for f in glob.glob(f"{output_prefix}*"):
            try:
                os.remove(f)
            except:
                pass
                
        # editcap -c <count> input output
        cmd = ["editcap", "-c", str(packets_per_file), self.pcap_path, output_prefix + ".pcap"]
        logger.info(f"正在分割 PCAP 文件: {' '.join(cmd)}")
        
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            logger.error(f"分割 PCAP 失败: {e}")
            return [self.pcap_path]
            
        # 获取生成的文件
        directory = os.path.dirname(self.pcap_path)
        base_name = os.path.basename(output_prefix)
        files = [os.path.join(directory, f) for f in os.listdir(directory) if f.startswith(base_name) and f.endswith(".pcap")]
        
        if not files:
             files = glob.glob(f"{output_prefix}*")
             
        files = [f for f in files if f != self.pcap_path]
        
        # 按名称排序确保顺序
        files.sort()
        
        logger.info(f"PCAP 分割完成，生成 {len(files)} 个文件。")
        return files

    def load_chunk(self, chunk_size=1000) -> Generator[list, None, None]:
        """
        分块读取 PCAP，返回 packet dict 列表。
        """
        try:
            import pyshark
        except ModuleNotFoundError as exc:
            raise RuntimeError("未安装 pyshark。请先执行: pip install pyshark") from exc

        # 修复某些环境下的 Pyshark asyncio 循环问题
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        logger.info(f"开始读取 PCAP 文件: {self.pcap_path}，块大小: {chunk_size}")
        cap = pyshark.FileCapture(self.pcap_path, keep_packets=False)
        chunk = []
        
        import time
        start_time = time.time()
        try:
            count = 0
            for packet in cap:
                p_dict = packet_to_dict(packet)
                if p_dict:
                    chunk.append(p_dict)
                    count += 1
                
                if len(chunk) >= chunk_size:
                    elapsed = time.time() - start_time
                    speed = count / elapsed if elapsed > 0 else 0
                    logger.info(f"已读取 {count} 个数据包... (当前速度: {speed:.2f} pkts/sec)")
                    yield chunk
                    chunk = []
            
            elapsed = time.time() - start_time
            speed = count / elapsed if elapsed > 0 else 0
            logger.info(f"PCAP 读取完成，共读取 {count} 个数据包。 (平均速度: {speed:.2f} pkts/sec)")
        except Exception as e:
            logger.error(f"读取 PCAP 出错: {e}")
        finally:
            cap.close()
            
        if chunk:
            yield chunk
