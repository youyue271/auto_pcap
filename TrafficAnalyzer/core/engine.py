import multiprocessing
from typing import List, Dict, Any, Tuple
import logging
import time
from .loader import PcapLoader, packet_to_dict
from .data_store import DataStore
from .strategy import BaseAnalyzer
from ..utils.flow_utils import get_flow_id

logger = logging.getLogger(__name__)

def _worker_process_file(args: Tuple[str, List[BaseAnalyzer]]) -> List[Dict]:
    """
    并行 IO 模式 Worker: 直接读取小文件并分析
    """
    file_path, analyzers = args
    results = []
    import pyshark
    import asyncio
    
    # 修复 asyncio
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    try:
        # 禁用 keep_packets 节省内存
        cap = pyshark.FileCapture(file_path, keep_packets=False)
        for packet in cap:
            # 转换数据包
            p_dict = packet_to_dict(packet)
            if not p_dict: continue
            
            # 计算 Flow ID
            fid = get_flow_id(p_dict)
            
            for analyzer in analyzers:
                try:
                    if analyzer.match_type(p_dict):
                        res = analyzer.analyze_parallel(p_dict)
                        if res:
                            res['flow_id'] = fid
                            res['timestamp'] = p_dict['timestamp']
                            res['analyzer_name'] = analyzer.name
                            if 'src_ip' not in res: res['src_ip'] = p_dict.get('src_ip')
                            if 'dst_ip' not in res: res['dst_ip'] = p_dict.get('dst_ip')
                            results.append(res)
                except Exception:
                    pass
        cap.close()
    except Exception as e:
        logger.error(f"处理文件 {file_path} 失败: {e}")
        
    return results

def _worker_process_chunk(args: Tuple[List[Dict], List[BaseAnalyzer]]) -> List[Dict]:
    """
    用于并行处理的 Worker 函数。
    必须是顶层函数以便于序列化 (picklable)。
    """
    chunk, analyzers = args
    results = []
    
    try:
        logger.debug(f"Worker 开始处理数据块，大小: {len(chunk)}")
        for packet in chunk:
            # 计算 Flow ID (五元组)
            fid = get_flow_id(packet)
            
            for analyzer in analyzers:
                try:
                    if analyzer.match_type(packet):
                        res = analyzer.analyze_parallel(packet)
                        if res:
                            # 丰富结果元数据
                            res['flow_id'] = fid
                            res['timestamp'] = packet['timestamp']
                            res['analyzer_name'] = analyzer.name
                            # 确保 src/dst 存在以便聚合
                            if 'src_ip' not in res: res['src_ip'] = packet.get('src_ip')
                            if 'dst_ip' not in res: res['dst_ip'] = packet.get('dst_ip')
                            results.append(res)
                except Exception as e:
                    # logger.error(f"分析器 {analyzer.name} 错误: {e}")
                    pass
    except Exception as e:
        logger.error(f"Worker 错误: {e}")
        
    return results

class Engine:
    def __init__(self, pcap_path: str, analyzers: List[BaseAnalyzer], use_db=False):
        self.pcap_path = pcap_path
        self.analyzers = analyzers
        self.store = DataStore(use_db=use_db)
        self.loader = PcapLoader(pcap_path)

    def _task_generator(self):
        for chunk in self.loader.load_chunk():
            yield (chunk, self.analyzers)

    def run(self, split_mode=False):
        start_time = time.time()
        logger.info("开始 Map 阶段 (并行特征提取)...")
        cpu_count = multiprocessing.cpu_count()
        logger.info(f"使用的 CPU 核心数: {cpu_count}")
        
        count = 0
        
        # 使用 multiprocessing Pool
        # imap 允许在结果生成时立即处理，有利于内存控制
        with multiprocessing.Pool(processes=cpu_count) as pool:
            
            if split_mode:
                logger.info("启用并行 IO 模式: 正在分割 PCAP 文件...")
                try:
                    # 动态调整切片大小: 目标是每个切片约 0.5MB
                    files = self.loader.split_pcap(target_chunk_size_mb=0.5)
                    task_args = [(f, self.analyzers) for f in files]
                    # 使用 imap_unordered 可能更快，但 imap 保持顺序也行。这里顺序不重要因为后面是存DB/内存。
                    result_iter = pool.imap_unordered(_worker_process_file, task_args)
                except Exception as e:
                    logger.error(f"并行 IO 初始化失败: {e}，回退到普通模式")
                    result_iter = pool.imap(_worker_process_chunk, self._task_generator())
            else:
                # map/imap 接受一个函数和一个可迭代对象。
                # 我们使用 _task_generator 生成 (chunk, analyzers) 元组
                result_iter = pool.imap(_worker_process_chunk, self._task_generator())
            
            batch_count = 0
            for batch_results in result_iter:
                batch_count += 1
                if batch_results:
                    self.store.save(batch_results)
                    count += len(batch_results)
                    if count % 1000 == 0:
                        logger.info(f"已提取 {count} 个特征...")
        
        map_duration = time.time() - start_time
        logger.info(f"Map 阶段完成。总特征数: {count}。耗时: {map_duration:.2f}秒")
        
        # Reduce 阶段
        self.reduce()
        
    def reduce(self):
        start_time = time.time()
        logger.info("开始 Reduce 阶段 (串行分析)...")
        
        # 1. 识别活跃分析器所需的聚合键 (Grouping Keys)
        grouping_map = {} # key -> list[analyzer]
        for analyzer in self.analyzers:
            key = analyzer.grouping_key
            if key not in grouping_map:
                grouping_map[key] = []
            grouping_map[key].append(analyzer)
            
        # 2. 遍历每个所需的聚合键
        for key, analyzers in grouping_map.items():
            analyzer_names = [a.name for a in analyzers]
            logger.info(f"正在按键聚合: '{key}'，涉及分析器: {analyzer_names}")
            
            # 3. 从 DataStore 获取分组数据
            group_count = 0
            for group_id, group_records in self.store.get_grouped_by(key):
                group_count += 1
                
                # 按分析器名称预过滤数据
                # 优化: 每个分组只做一次
                analyzer_data_map = {}
                for r in group_records:
                    aname = r.get('analyzer_name')
                    if aname not in analyzer_data_map:
                        analyzer_data_map[aname] = []
                    analyzer_data_map[aname].append(r)
                
                # 4. 对该分组运行每个分析器
                for analyzer in analyzers:
                    # 获取该分析器的数据
                    data = analyzer_data_map.get(analyzer.name, [])
                    
                    if data:
                        try:
                            alerts = analyzer.analyze_serial(data)
                            if alerts:
                                for alert in alerts:
                                    print(f"[警报] {analyzer.name} 在 {key}={group_id}: {alert}")
                        except Exception as e:
                            logger.error(f"分析器 {analyzer.name} 串行分析错误: {e}")
            
            logger.info(f"键 '{key}' 处理完成，共处理 {group_count} 个分组。")

        reduce_duration = time.time() - start_time
        logger.info(f"Reduce 阶段完成。耗时: {reduce_duration:.2f}秒")
        logger.info("分析全部完成。")
